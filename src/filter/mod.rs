//! Threat detection, location-based filtering, and smart deduplication
//! for Ukrainian air-raid / military alert channels.
//!
//! Supports **both Ukrainian and Russian** message text – most real-world
//! alert channels post in a mix of both.
pub mod filter_tests;
pub mod threat_keywords;
pub mod threat_kind;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::filter::threat_keywords::{NATIONWIDE_KEYWORDS, THREAT_KEYWORDS, is_urgent};
use crate::filter::threat_kind::ThreatKind;

/// Returns `true` when the message is a nationwide alert that should bypass
/// location filtering.
fn is_nationwide(lower: &str) -> bool {
    NATIONWIDE_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn has_live_movement_markers(lower: &str) -> bool {
    let markers = [
        "курсом на",
        "у бік",
        "в бік",
        "вектором на",
        "летить",
        "летят",
        "руха",
        "рух бпла",
        "швидкісна ціль",
        "скоростная цель",
        "ціль на",
        "цель на",
        "заліта",
        "напрямку",
    ];
    markers.iter().any(|m| lower.contains(m))
}

/// Broad stems for non-local Ukrainian regions/cities that often appear in
/// trajectory messages. Used to prevent local-context fallback from
/// re-labeling clearly non-local alerts as local.
const NONLOCAL_REGION_STEMS: &[&str] = &[
    "харків",
    "харьков",
    "одес",
    "никола",
    "микола",
    "херсон",
    "запор",
    "дніпр",
    "днепр",
    "черніг",
    "черниг",
    "черкас",
    "сум",
    "полтав",
    "кропив",
    "кіровоград",
    "кировоград",
    "вінниц",
    "винниц",
    "житомир",
    "львів",
    "львов",
    "терноп",
    "рівн",
    "ровен",
    "хмельниц",
    "чернів",
    "чернов",
    "луцьк",
    "волин",
    "ужгород",
    "закарпат",
    "івано",
    "ивано",
    "донеч",
    "донец",
    "луган",
    "крим",
    "крыма",
    "криму",
];

/// Returns `true` for long recap/statistics posts that list launch totals,
/// interceptions and results, but are not immediate trajectory alerts.
fn is_informational_report(lower: &str) -> bool {
    // Keep clearly live movement/trajectory alerts.
    if has_live_movement_markers(lower) {
        return false;
    }

    let report_markers = [
        "збито/подавлено",
        "станом на",
        "у ніч на",
        "усього",
        "за попередніми даними",
        "зафіксовано",
        "влучання",
        "падіння збитих",
        "інформація щодо",
        "разом – до перемоги",
        "тримаймо небо",
    ];
    let marker_hits = report_markers
        .iter()
        .filter(|m| lower.contains(**m))
        .count();
    let line_breaks = lower.matches('\n').count();
    let bullet_lines = lower.matches("\n- ").count() + lower.matches("\n•").count();
    let digit_count = lower.chars().filter(|c| c.is_ascii_digit()).count();

    marker_hits >= 2 && (line_breaks >= 10 || bullet_lines >= 3 || digit_count >= 20)
}

/// Returns `true` for "situation is clear / no longer observed" updates that
/// are not explicit all-clear alerts and should be suppressed.
fn is_negative_update(lower: &str) -> bool {
    // Explicit all-clear ("відбій", "чисте небо", etc.) is handled separately.
    if detect_threats(lower).contains(&ThreatKind::AllClear) {
        return false;
    }

    let negative_markers = [
        "не спостеріга",
        "не фіксу",
        "чисто",
        "все зник",
        "зникла",
        "більше не спостеріга",
        "по цирконам минус",
        "минус",
    ];
    let has_negative = negative_markers.iter().any(|m| lower.contains(m))
        || lower.trim() == "все"
        || lower.trim() == "все.";
    if !has_negative {
        return false;
    }

    // "поки чисто / не фіксуються, можливі повторні пуски" is still
    // a status update, not a fresh active launch message.
    if lower.contains("повторн")
        && (lower.contains("можлив") || lower.contains("ймовір"))
        && lower.contains("пуск")
    {
        return true;
    }

    // Keep clearly active updates.
    let active_markers = [
        "курсом на",
        "у бік",
        "в бік",
        "вектор",
        "летить",
        "летят",
        "руха",
        "пуск",
        "вихід",
        "виход",
        "загроз",
        "увага",
        "ще ",
    ];
    !active_markers.iter().any(|m| lower.contains(m))
}

// ───────────────────────────── Detection ─────────────────────────────────

/// Scan lowercased text and return the set of detected threat kinds.
/// More specific kinds suppress generic ones.
fn detect_threats(lower: &str) -> Vec<ThreatKind> {
    // Be tolerant to call sites: normalize here even though process() already
    // lowercases once.
    let lower_owned = lower.to_lowercase();
    let lower = lower_owned.as_str();

    fn contains_standalone_token(lower: &str, token: &str) -> bool {
        let mut start = 0;
        while let Some(rel) = lower[start..].find(token) {
            let s = start + rel;
            let e = s + token.len();
            let prev_ok = lower[..s]
                .chars()
                .next_back()
                .map(|c| !c.is_alphanumeric())
                .unwrap_or(true);
            let next_ok = lower[e..]
                .chars()
                .next()
                .map(|c| !c.is_alphanumeric())
                .unwrap_or(true);
            if prev_ok && next_ok {
                return true;
            }
            start = e;
        }
        false
    }

    fn detect_combo_threats(lower: &str) -> Vec<ThreatKind> {
        let mut out = Vec::new();

        // Cruise missile shorthand used heavily in real channels:
        // "КР курсом на ...", "2х КР на ...".
        if contains_standalone_token(lower, "кр")
            && (lower.contains("курс")
                || lower.contains("ракет")
                || lower.contains("груп")
                || lower.contains("на "))
        {
            out.push(ThreatKind::CruiseMissile);
        }

        // Strategic aviation shorthand pattern:
        // "борти СА ... в повітрі", "зліт ... бортів СА".
        let has_bort = lower.contains("борт");
        let has_strat_marker = lower.contains("са")
            || lower.contains("стратегічн")
            || lower.contains("стратегическ")
            || lower.contains("ту-95")
            || lower.contains("ту-160");
        let has_airborne_marker = lower.contains("в повітрі")
            || lower.contains("в повітря")
            || lower.contains("в воздухе")
            || lower.contains("зліт");
        if has_bort && has_strat_marker && has_airborne_marker {
            out.push(ThreatKind::Aircraft);
        }

        // High-speed target shorthand from alert channels:
        // "швидкісна ціль ...", "скоростная цель ...".
        let has_fast_marker = lower.contains("швидкісн")
            || lower.contains("скоростн")
            || lower.contains("высокоскорост");
        let has_target_marker = lower.contains("ціль") || lower.contains("цель");
        if has_fast_marker && has_target_marker {
            out.push(ThreatKind::Missile);
        }

        out
    }

    let mut found: Vec<ThreatKind> = Vec::new();

    for &(kind, stems) in THREAT_KEYWORDS {
        if stems.iter().any(|s| lower.contains(s)) {
            found.push(kind);
        }
    }
    for kind in detect_combo_threats(lower) {
        if !found.contains(&kind) {
            found.push(kind);
        }
    }

    // Suppress generic "Missile" if a specific missile type already matched.
    if found.contains(&ThreatKind::Ballistic)
        || found.contains(&ThreatKind::CruiseMissile)
        || found.contains(&ThreatKind::Hypersonic)
    {
        found.retain(|k| *k != ThreatKind::Missile);
    }
    // Treat Zircon/hypersonic reports as a single specific class.
    // Avoid dual-labeling them as "CruiseMissile + Hypersonic".
    if found.contains(&ThreatKind::Hypersonic) {
        found.retain(|k| *k != ThreatKind::CruiseMissile);
    }
    // Suppress generic "Other" if anything more specific matched
    // (including AllClear — "відбій тривоги" shouldn't also produce Other).
    if found.iter().any(|k| !matches!(k, ThreatKind::Other)) {
        found.retain(|k| *k != ThreatKind::Other);
    }
    // AllClear + active threat in the same message → keep both (unusual but
    // handle gracefully)

    found
}

// ───────────────────────────── Proximity ─────────────────────────────────

/// How close the threat is to the user.  Higher = closer = more urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proximity {
    None = 0,
    Oblast = 1,
    City = 2,
    District = 3,
}

impl Proximity {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::District => "🔴 РАЙОН",
            Self::City => "🟠 МІСТО",
            Self::Oblast => "🟡 ОБЛАСТЬ",
            Self::None => "",
        }
    }
}

// ───────────────────────── Location config ────────────────────────────────

/// User's location expressed as lists of keyword variants for each level.
/// Include **both Ukrainian and Russian** name forms in your env vars!
///
/// Example for Kyiv:
/// ```env
/// MY_OBLAST=Київськ,Киевск,Kyiv
/// MY_CITY=Київ,Киев,Kyiv,Києв
/// MY_DISTRICT=Шевченківськ,Шевченковск
/// ```
#[derive(Debug, Clone)]
pub struct LocationConfig {
    pub oblast: Vec<String>,
    pub city: Vec<String>,
    pub district: Vec<String>,
}

impl LocationConfig {
    /// Build from comma-separated env vars.  Each value is lowercased and
    /// trimmed.  Empty / missing env vars produce an empty list.
    pub fn from_env() -> Self {
        fn parse(key: &str) -> Vec<String> {
            std::env::var(key)
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        }

        Self {
            oblast: parse("MY_OBLAST"),
            city: parse("MY_CITY"),
            district: parse("MY_DISTRICT"),
        }
    }

    fn contains_with_boundary(lower: &str, kw: &str) -> bool {
        if kw.is_empty() {
            return false;
        }
        let mut start = 0;
        while let Some(rel) = lower[start..].find(kw) {
            let s = start + rel;
            let e = s + kw.len();
            let prev_ok = lower[..s]
                .chars()
                .next_back()
                .map(|c| !c.is_alphabetic())
                .unwrap_or(true);
            let next_ok = lower[e..]
                .chars()
                .next()
                .map(|c| !c.is_alphabetic())
                .unwrap_or(true);
            if prev_ok && next_ok {
                return true;
            }
            start = e;
        }
        false
    }

    /// Return the highest proximity level that matches `lower` (already
    /// lowercased text).
    fn check(&self, lower: &str) -> Proximity {
        let (district, city, oblast) = self.match_levels(lower);
        if district {
            return Proximity::District;
        }
        if city {
            return Proximity::City;
        }
        if oblast {
            return Proximity::Oblast;
        }
        Proximity::None
    }

    /// Return booleans for district/city/oblast matches.
    fn match_levels(&self, lower: &str) -> (bool, bool, bool) {
        fn matches_loc_kw(lower: &str, kw: &str) -> bool {
            if kw.contains(char::is_whitespace) {
                // Phrases like "на київ" should not match "на київщину".
                LocationConfig::contains_with_boundary(lower, kw)
            } else {
                // Stems like "київщин", "харківськ" must match declensions.
                lower.contains(kw)
            }
        }
        let district = self.district.iter().any(|kw| matches_loc_kw(lower, kw));
        let city = self.city.iter().any(|kw| matches_loc_kw(lower, kw));
        let oblast = self.oblast.iter().any(|kw| matches_loc_kw(lower, kw));
        (district, city, oblast)
    }
}

// ─────────────────────────── Alert filter ─────────────────────────────────

/// Context keywords that indicate specific threat types when "ціль"/"цель"
/// (target) is mentioned. These are checked against recent channel history.
const TARGET_CONTEXT_KEYWORDS: &[(ThreatKind, &[&str])] = &[
    (
        ThreatKind::Ballistic,
        &[
            "балістик",
            "баллистик",
            "іскандер",
            "искандер",
            "кінжал",
            "кинжал",
        ],
    ),
    (
        ThreatKind::CruiseMissile,
        &["крилат", "крылат", "калібр", "калибр", "х-101", "x-101"],
    ),
    (
        ThreatKind::Shahed,
        &[
            "шахед",
            "shahed",
            "герань",
            "geran",
            "мопед",
            "дрон",
            "бпла",
        ],
    ),
];

/// A single message in the channel context window.
#[derive(Clone)]
struct ContextMessage {
    timestamp: Instant,
    text_lower: String,
    detected_threats: Vec<ThreatKind>,
    detected_proximity: Proximity,
}

/// Per-channel context window that tracks recent messages to infer
/// threat type from ambiguous words like "ціль" (target).
struct ChannelContext {
    messages: Vec<ContextMessage>,
    window_duration: Duration,
}

impl ChannelContext {
    fn new(window_duration: Duration) -> Self {
        Self {
            messages: Vec::new(),
            window_duration,
        }
    }

    /// Add a new message to the context window.
    fn add(&mut self, text_lower: String, threats: Vec<ThreatKind>, proximity: Proximity) {
        self.evict();
        self.messages.push(ContextMessage {
            timestamp: Instant::now(),
            text_lower,
            detected_threats: threats,
            detected_proximity: proximity,
        });
        // Keep max 20 messages to avoid unbounded growth
        if self.messages.len() > 20 {
            self.messages.remove(0);
        }
    }

    /// Remove messages older than the window duration.
    fn evict(&mut self) {
        let now = Instant::now();
        self.messages
            .retain(|msg| now.duration_since(msg.timestamp) < self.window_duration);
    }

    /// Check if the message contains trigger words ("ціль", "вихід", etc.)
    /// and infer the threat type from recent channel context.
    fn infer_threat_from_triggers(&mut self, lower: &str) -> Option<ThreatKind> {
        fn has_celi_with_boundary(lower: &str) -> bool {
            let mut start = 0;
            while let Some(rel) = lower[start..].find("цели") {
                let end = start + rel + "цели".len();
                let boundary = lower[end..]
                    .chars()
                    .next()
                    .map(|c| !c.is_alphabetic())
                    .unwrap_or(true);
                if boundary {
                    return true;
                }
                start = end;
            }
            false
        }

        // Check for target keywords
        let has_target = lower.contains("ціль")
            || lower.contains("цілі")
            || lower.contains("цілей")
            || lower.contains("цель")
            || has_celi_with_boundary(lower)
            || lower.contains("целей");

        // Check for launch-related keywords (follow-up to an ongoing threat)
        let has_launch =
            lower.contains("вихід") || lower.contains("виход") || lower.contains("выход");

        if !has_target && !has_launch {
            return None;
        }

        self.evict();

        // Look through recent messages (most recent first) to find threat context
        for msg in self.messages.iter().rev() {
            // Check if any context keywords match
            for &(threat_kind, keywords) in TARGET_CONTEXT_KEYWORDS {
                if keywords.iter().any(|kw| msg.text_lower.contains(kw)) {
                    debug!(
                        "Context: inferred {threat_kind:?} from recent message containing {:?}",
                        keywords
                            .iter()
                            .find(|kw| msg.text_lower.contains(**kw))
                            .unwrap()
                    );
                    return Some(threat_kind);
                }
            }

            // Also check detected threats from previous messages
            if let Some(&threat) = msg.detected_threats.iter().find(|t| {
                matches!(
                    t,
                    ThreatKind::Ballistic
                        | ThreatKind::CruiseMissile
                        | ThreatKind::Shahed
                        | ThreatKind::Hypersonic
                )
            }) {
                debug!("Context: inferred {threat:?} from recent detected threats");
                return Some(threat);
            }
        }

        // Default to generic Missile if we can't infer from context
        debug!("Context: no recent context for trigger, defaulting to Missile");
        Some(ThreatKind::Missile)
    }

    /// Return the most recent specific threat from the context window.
    /// Used when the current message has a location or urgency but no
    /// explicit threat keyword.
    fn infer_recent_threat(&mut self) -> Option<ThreatKind> {
        self.evict();
        for msg in self.messages.iter().rev() {
            if let Some(&threat) = msg
                .detected_threats
                .iter()
                .filter(|t| !matches!(t, ThreatKind::Other | ThreatKind::AllClear))
                .max_by_key(|t| t.specificity())
            {
                debug!("Context: inferred recent threat {threat:?}");
                return Some(threat);
            }
        }
        None
    }

    /// Return the most recent non-None proximity from the context window.
    /// Used when the current message has a threat or urgency but no
    /// location match.
    fn infer_location(&mut self) -> Proximity {
        self.evict();
        for msg in self.messages.iter().rev() {
            if msg.detected_proximity != Proximity::None {
                debug!("Context: inferred location {:?}", msg.detected_proximity);
                return msg.detected_proximity;
            }
        }
        Proximity::None
    }
}

/// Entry stored per `ThreatKind` in the dedup cache.
struct DedupEntry {
    sent_at: Instant,
    max_proximity: Proximity,
    /// Union of significant threat kinds already sent for this primary kind
    /// during the dedup window.
    seen_signature: u16,
    /// Whether a nationwide variant of this primary threat has already
    /// been forwarded during the dedup window.
    seen_nationwide: bool,
    /// `true` when the cached message itself was an urgency-tagged one
    /// ("повторно", "додатково", …).
    was_urgent: bool,
    /// Timestamp of the last forwarded urgent re-alert for this primary kind.
    last_urgent_at: Option<Instant>,
    /// Stable channel peer-id.  Used to distinguish a genuine
    /// same-channel re-alert from cross-channel echo spam.
    last_channel_id: i64,
}

fn threat_bit(kind: ThreatKind) -> u16 {
    match kind {
        ThreatKind::Ballistic => 1 << 0,
        ThreatKind::Hypersonic => 1 << 1,
        ThreatKind::CruiseMissile => 1 << 2,
        ThreatKind::GuidedBomb => 1 << 3,
        ThreatKind::Missile => 1 << 4,
        ThreatKind::Shahed => 1 << 5,
        ThreatKind::ReconDrone => 1 << 6,
        ThreatKind::Aircraft => 1 << 7,
        ThreatKind::AllClear => 0,
        ThreatKind::Other => 0,
    }
}

fn threat_signature(threats: &[ThreatKind]) -> u16 {
    threats.iter().fold(0u16, |acc, t| acc | threat_bit(*t))
}

/// Result of context-aware detection.
struct ContextDetection {
    threats: Vec<ThreatKind>,
    proximity: Proximity,
    nationwide: bool,
}

#[derive(Default)]
struct NegativeStatusState {
    latched_for_wave: bool,
    last_sent_at: Option<Instant>,
}

/// Stateful filter: detects threats, checks location, deduplicates.
pub struct AlertFilter {
    location: LocationConfig,
    dedup_window: Duration,
    cache: HashMap<ThreatKind, DedupEntry>,
    /// Per-channel context windows for better threat inference
    channel_contexts: HashMap<i64, ChannelContext>,
    /// Duration for per-channel context windows.
    context_window: Duration,
    /// Minimum delay between forwarded urgent re-alerts from the same channel
    /// for the same primary threat kind.
    urgent_same_channel_cooldown: Duration,
    /// When `true`, messages that contain threat keywords but do NOT match
    /// any user location are still forwarded (with `Proximity::None`).
    forward_all_threats: bool,
    /// Per-channel state for one-time negative-status updates
    /// ("не фіксуються", "більше не спостерігається", ...).
    negative_status_state: HashMap<i64, NegativeStatusState>,
    /// Minimum delay between forwarded negative-status updates per channel.
    negative_status_cooldown: Duration,
}

impl AlertFilter {
    /// Construct from environment variables.
    ///
    /// | Env var                | Default | Purpose                                 |
    /// |------------------------|---------|-----------------------------------------|
    /// | `MY_OBLAST`            | —       | Comma-separated oblast name variants    |
    /// | `MY_CITY`              | —       | Comma-separated city name variants      |
    /// | `MY_DISTRICT`          | —       | Comma-separated district name variants  |
    /// | `DEDUP_WINDOW_SECS`    | `180`   | Sliding dedup window in seconds         |
    /// | `CONTEXT_WINDOW_SECS`  | `300`   | Channel context window in seconds       |
    /// | `URGENT_COOLDOWN_SECS` | `20`    | Same-channel urgent re-alert cooldown   |
    /// | `NEGATIVE_STATUS_COOLDOWN_SECS` | `120` | Per-channel negative update cooldown |
    /// | `FORWARD_ALL_THREATS`  | `false` | Forward threats outside your area too   |
    pub fn from_env() -> Self {
        let location = LocationConfig::from_env();
        let dedup_secs: u64 = std::env::var("DEDUP_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(180);
        let context_secs: u64 = std::env::var("CONTEXT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let urgent_cooldown_secs: u64 = std::env::var("URGENT_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        let negative_status_cooldown_secs: u64 = std::env::var("NEGATIVE_STATUS_COOLDOWN_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        let forward_all: bool = std::env::var("FORWARD_ALL_THREATS")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            location,
            dedup_window: Duration::from_secs(dedup_secs),
            cache: HashMap::new(),
            channel_contexts: HashMap::new(),
            context_window: Duration::from_secs(context_secs),
            urgent_same_channel_cooldown: Duration::from_secs(urgent_cooldown_secs),
            forward_all_threats: forward_all,
            negative_status_state: HashMap::new(),
            negative_status_cooldown: Duration::from_secs(negative_status_cooldown_secs),
        }
    }

    /// Evict expired entries (called lazily on each `process()`).
    fn evict(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, e| now.duration_since(e.sent_at) < self.dedup_window);

        // Drop stale per-channel windows to prevent unbounded map growth.
        self.channel_contexts.retain(|_, ctx| {
            ctx.evict();
            !ctx.messages.is_empty()
        });
        // Keep negative-status map bounded to channels still present in context.
        self.negative_status_state
            .retain(|channel_id, _| self.channel_contexts.contains_key(channel_id));
    }

    /// Back-compat wrapper used by tests. Prefer [`process_with_id`] when
    /// you have a stable channel peer-id.
    pub fn process(&mut self, channel_title: &str, text: &str) -> Option<String> {
        // Use channel title hash as a pseudo-id so tests still exercise dedup.
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        channel_title.hash(&mut h);
        self.process_with_id(h.finish() as i64, channel_title, text)
    }

    /// Main entry point.  Returns `Some(formatted_alert)` when the message
    /// should be forwarded, or `None` to suppress.
    ///
    /// `channel_id` must be a **stable** identifier for the source channel
    /// (e.g. `peer.id().bare_id()` from grammers) so that dedup survives
    /// channel title changes.
    pub fn process_with_id(
        &mut self,
        channel_id: i64,
        channel_title: &str,
        text: &str,
    ) -> Option<String> {
        let lower = text.to_lowercase();
        if is_informational_report(&lower) {
            debug!("Informational recap/statistics post – skipping");
            return None;
        }
        if is_negative_update(&lower) {
            return self.handle_negative_status_update(channel_id, channel_title, text, &lower);
        }

        let det = self.detect_with_context(channel_id, &lower, channel_title)?;
        self.on_active_threat_seen(channel_id, &det.threats);

        // AllClear fast-path.
        if let Some(alert) = self.try_all_clear(&det.threats, channel_title, text) {
            return Some(alert);
        }

        if det.proximity == Proximity::None && !det.nationwide && !self.forward_all_threats {
            debug!("Threat detected but no location match – skipping");
            return None;
        }

        self.dedup_and_format(
            channel_id,
            &det.threats,
            det.proximity,
            det.nationwide,
            &lower,
            channel_title,
            text,
        )
    }

    /// Async variant that runs the LLM secondary filter after keyword
    /// detection but before formatting.  Falls back to keyword-only
    /// when the LLM is disabled or errors out.
    pub async fn process_with_llm(
        &mut self,
        channel_id: i64,
        channel_title: &str,
        text: &str,
        llm: &crate::llm::LlmFilter,
    ) -> Option<String> {
        let lower = text.to_lowercase();
        if is_informational_report(&lower) {
            debug!("Informational recap/statistics post – skipping");
            return None;
        }
        if is_negative_update(&lower) {
            return self.handle_negative_status_update(channel_id, channel_title, text, &lower);
        }

        let det = self.detect_with_context(channel_id, &lower, channel_title)?;

        // AllClear fast-path (no LLM needed).
        if let Some(alert) = self.try_all_clear(&det.threats, channel_title, text) {
            return Some(alert);
        }

        let proximity = det.proximity;
        let nationwide = det.nationwide;
        if proximity == Proximity::None && !nationwide && !self.forward_all_threats {
            debug!("Threat detected but no location match – skipping");
            return None;
        }

        // ── LLM verification (async) ──
        let threats = if llm.is_enabled() {
            let verified = llm.verify(text, &det.threats, proximity, nationwide).await;
            if verified.is_empty() {
                debug!("LLM says not an active alert – suppressing");
                return None;
            }
            // Update context with more accurate LLM-verified threats.
            if let Some(ctx) = self.channel_contexts.get_mut(&channel_id) {
                if let Some(last) = ctx.messages.last_mut() {
                    last.detected_threats = verified.clone();
                }
            }
            verified
        } else {
            det.threats
        };
        self.on_active_threat_seen(channel_id, &threats);

        self.dedup_and_format(
            channel_id,
            &threats,
            proximity,
            nationwide,
            &lower,
            channel_title,
            text,
        )
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// Run keyword detection + context-based inference for threats AND
    /// location.  Stores the message in the channel context window
    /// (even when returning `None`) so that subsequent messages can
    /// infer from it.
    fn detect_with_context(
        &mut self,
        channel_id: i64,
        lower: &str,
        channel_title: &str,
    ) -> Option<ContextDetection> {
        // Phase 1 — raw keyword detection (borrows &self only)
        let mut threats = detect_threats(lower);
        let (mut proximity, nationwide) = self.resolve_location(lower, channel_title);
        let explicit_nonlocal = self.has_explicit_nonlocal_location(lower);
        let urgent = is_urgent(lower);

        // Phase 2 — context inference (borrows &mut self via get_context)
        {
            let context = self.get_context(channel_id);

            // 2a. Trigger-word inference ("ціль", "вихід", etc.)
            //     Only when no explicit threat keyword was already detected.
            if threats.is_empty() {
                if let Some(inferred) = context.infer_threat_from_triggers(lower) {
                    debug!("Adding {inferred:?} from trigger inference");
                    threats.push(inferred);
                }
            }

            // 2b. Location present or urgent, but no threat → infer threat from context.
            if threats.is_empty() && (proximity != Proximity::None || urgent) {
                if let Some(inferred) = context.infer_recent_threat() {
                    debug!("Inferred {inferred:?} from context (no threat keyword)");
                    threats.push(inferred);
                }
            }

            // 2c. Have threat or urgency, but no location → infer location once from context.
            if proximity == Proximity::None
                && !nationwide
                && !explicit_nonlocal
                && (!threats.is_empty() || urgent)
            {
                let ctx_prox = context.infer_location();
                let ctx_prox = Self::cap_context_proximity(ctx_prox);
                if ctx_prox != Proximity::None {
                    debug!("Inferred location {ctx_prox:?} from context");
                    proximity = ctx_prox;
                }
            }

            // Store in context (even if we won't forward — seeds future inference)
            if !threats.is_empty() || proximity != Proximity::None {
                context.add(lower.to_owned(), threats.clone(), proximity);
            }
        }

        // Phase 3 — refine generic Missile using recent cross-channel context.
        // During dense bursts, "4 ракети на Київ" should align with the
        // already-established specific threat type (e.g. Ballistic).
        if threats.len() == 1 && threats[0] == ThreatKind::Missile {
            if let Some(inferred) = self.infer_recent_global_specific_threat() {
                debug!("Refined generic Missile -> {inferred:?} from global context");
                threats[0] = inferred;
            }
        }
        // Phase 4 — refine generic Other during clearly live movement.
        // Example: "Залітає ... Українка ..." inside an active missile wave
        // should inherit the recent missile-family context.
        if threats.len() == 1
            && threats[0] == ThreatKind::Other
            && has_live_movement_markers(lower)
            && (proximity != Proximity::None || nationwide || urgent)
        {
            if let Some(inferred) = self.infer_recent_global_specific_threat() {
                debug!("Refined Other -> {inferred:?} from global context");
                threats[0] = inferred;
            }
        }

        if threats.is_empty() {
            debug!("No threat keywords found – skipping");
            return None;
        }

        Some(ContextDetection {
            threats,
            proximity,
            nationwide,
        })
    }

    /// Get (or create) the per-channel context window.
    fn get_context(&mut self, channel_id: i64) -> &mut ChannelContext {
        let window = self.context_window;
        self.channel_contexts
            .entry(channel_id)
            .or_insert_with(|| ChannelContext::new(window))
    }

    /// Infer the most recent specific threat across all channel windows.
    /// Uses only missile-family specific classes to avoid cross-wave bleed
    /// (e.g. generic "ракети" accidentally inheriting Shahed).
    fn infer_recent_global_specific_threat(&mut self) -> Option<ThreatKind> {
        let mut best: Option<(Instant, ThreatKind)> = None;

        for ctx in self.channel_contexts.values_mut() {
            ctx.evict();
            for msg in ctx.messages.iter().rev() {
                if let Some(&threat) = msg.detected_threats.iter().find(|t| {
                    matches!(
                        t,
                        ThreatKind::Ballistic
                            | ThreatKind::Hypersonic
                            | ThreatKind::CruiseMissile
                            | ThreatKind::GuidedBomb
                    )
                }) {
                    match best {
                        Some((ts, _)) if ts >= msg.timestamp => {}
                        _ => best = Some((msg.timestamp, threat)),
                    }
                }
            }
        }

        best.map(|(_, t)| t)
    }

    fn on_active_threat_seen(&mut self, channel_id: i64, threats: &[ThreatKind]) {
        if threats
            .iter()
            .any(|t| !matches!(t, ThreatKind::AllClear | ThreatKind::Other))
        {
            let entry = self.negative_status_state.entry(channel_id).or_default();
            if entry.latched_for_wave {
                debug!("Negative-status latch reset for channel {channel_id}");
            }
            entry.latched_for_wave = false;
        }
    }

    fn handle_negative_status_update(
        &mut self,
        channel_id: i64,
        channel_title: &str,
        text: &str,
        lower: &str,
    ) -> Option<String> {
        self.evict();
        let now = Instant::now();

        let has_recent_threat = if let Some(ctx) = self.channel_contexts.get_mut(&channel_id) {
            ctx.infer_recent_threat().is_some()
        } else {
            false
        };
        if !has_recent_threat {
            debug!("Negative-status update without active threat context – skipping");
            return None;
        }

        {
            let state = self.negative_status_state.entry(channel_id).or_default();
            if state.latched_for_wave {
                debug!("Negative-status already sent for current wave (channel {channel_id})");
                return None;
            }
            if let Some(ts) = state.last_sent_at {
                if now.duration_since(ts) < self.negative_status_cooldown {
                    debug!(
                        "Negative-status throttled (channel {channel_id}, cooldown={}s)",
                        self.negative_status_cooldown.as_secs()
                    );
                    return None;
                }
            }
        }

        let (mut proximity, nationwide) = self.resolve_location(lower, channel_title);
        let explicit_nonlocal = self.has_explicit_nonlocal_location(lower);
        if proximity == Proximity::None && !nationwide && !explicit_nonlocal {
            if let Some(ctx) = self.channel_contexts.get_mut(&channel_id) {
                let ctx_prox = ctx.infer_location();
                let ctx_prox = Self::cap_context_proximity(ctx_prox);
                if ctx_prox != Proximity::None {
                    proximity = ctx_prox;
                }
            }
        }

        let state = self.negative_status_state.entry(channel_id).or_default();
        state.latched_for_wave = true;
        state.last_sent_at = Some(now);
        Some(self.format_negative_status(proximity, nationwide, channel_title, text))
    }

    /// If the threats are a sole AllClear, format and clear cache.
    /// Returns `Some(alert)` to short-circuit, or `None` to continue.
    fn try_all_clear(
        &mut self,
        threats: &[ThreatKind],
        channel_title: &str,
        text: &str,
    ) -> Option<String> {
        if threats.len() == 1 && threats.contains(&ThreatKind::AllClear) {
            let alert = self.format(threats, Proximity::None, channel_title, text, false, false);
            self.cache.clear();
            // Clear channel contexts to prevent stale inference into the next wave.
            self.channel_contexts.clear();
            self.negative_status_state.clear();
            return Some(alert);
        }
        None
    }

    /// Determine proximity and nationwide status from lowercased text.
    fn resolve_location(&self, lower: &str, channel_title: &str) -> (Proximity, bool) {
        let lower_title = channel_title.to_lowercase();
        let nationwide = is_nationwide(lower);
        let explicit_nonlocal = self.has_explicit_nonlocal_location(lower);
        let (district_m, city_m, oblast_m) = self.location.match_levels(lower);

        // "на Київ та область" should be treated as oblast scope (broader risk).
        let text_proximity = if district_m {
            Proximity::District
        } else if city_m && (oblast_m || lower.contains("област")) {
            Proximity::Oblast
        } else if city_m {
            Proximity::City
        } else if oblast_m {
            Proximity::Oblast
        } else {
            Proximity::None
        };
        let proximity = if nationwide {
            if text_proximity != Proximity::None {
                text_proximity
            } else if !explicit_nonlocal {
                let title_loc = self.location.check(&lower_title);
                if title_loc == Proximity::None {
                    Proximity::Oblast
                } else {
                    title_loc
                }
            } else {
                Proximity::Oblast
            }
        } else if text_proximity != Proximity::None {
            text_proximity
        } else if !explicit_nonlocal {
            self.location.check(&lower_title)
        } else {
            Proximity::None
        };
        (proximity, nationwide)
    }

    fn cap_context_proximity(p: Proximity) -> Proximity {
        match p {
            Proximity::District => Proximity::City,
            other => other,
        }
    }

    fn has_explicit_nonlocal_location(&self, lower: &str) -> bool {
        if self.location.check(lower) != Proximity::None {
            return false;
        }
        NONLOCAL_REGION_STEMS
            .iter()
            .any(|stem| lower.contains(stem))
    }

    /// Check urgency, run dedup, update cache, and format.
    /// Returns `None` when the message is suppressed by dedup.
    fn dedup_and_format(
        &mut self,
        channel_id: i64,
        threats: &[ThreatKind],
        proximity: Proximity,
        nationwide: bool,
        lower: &str,
        channel_title: &str,
        text: &str,
    ) -> Option<String> {
        let urgent = is_urgent(lower);
        self.evict();
        let now = Instant::now();

        let primary = threats.iter().copied().max_by_key(|k| k.specificity())?;
        let signature = threat_signature(threats);

        if let Some(entry) = self.cache.get(&primary) {
            if proximity > entry.max_proximity {
                debug!(
                    "Dedup upgrade: {primary:?} {:?} → {proximity:?}",
                    entry.max_proximity
                );
            } else if nationwide && !entry.seen_nationwide {
                debug!("Dedup: first nationwide alert for {primary:?} – forwarding");
            } else if signature & !entry.seen_signature != 0 {
                debug!("Dedup: new threat combination for {primary:?} – forwarding");
            } else if urgent && !entry.was_urgent {
                debug!("Dedup: first urgent re-alert for {primary:?} – forwarding");
            } else if urgent && entry.last_channel_id == channel_id {
                let can_forward = entry.last_urgent_at.map_or(true, |ts| {
                    now.duration_since(ts) >= self.urgent_same_channel_cooldown
                });
                if can_forward {
                    debug!("Dedup: same-channel re-alert for {primary:?} – forwarding");
                } else {
                    debug!(
                        "Dedup: same-channel urgent throttled for {primary:?} (cooldown={}s)",
                        self.urgent_same_channel_cooldown.as_secs()
                    );
                    return None;
                }
            } else {
                debug!(
                    "Dedup: {primary:?}/{proximity:?} suppressed (already sent {:?}, urgent={}, ch_id={})",
                    entry.max_proximity, entry.was_urgent, entry.last_channel_id,
                );
                return None;
            }
        }

        let prev_max = self.cache.get(&primary).map(|e| e.max_proximity);
        self.cache.insert(
            primary,
            DedupEntry {
                sent_at: now,
                max_proximity: prev_max.map_or(proximity, |p| proximity.max(p)),
                seen_signature: self
                    .cache
                    .get(&primary)
                    .map_or(signature, |e| e.seen_signature | signature),
                seen_nationwide: self
                    .cache
                    .get(&primary)
                    .map_or(nationwide, |e| e.seen_nationwide || nationwide),
                was_urgent: urgent,
                last_urgent_at: if urgent {
                    Some(now)
                } else {
                    self.cache.get(&primary).and_then(|e| e.last_urgent_at)
                },
                last_channel_id: channel_id,
            },
        );

        let alert = self.format(threats, proximity, channel_title, text, urgent, nationwide);
        Some(alert)
    }

    fn format(
        &self,
        threats: &[ThreatKind],
        proximity: Proximity,
        channel_title: &str,
        text: &str,
        urgent: bool,
        nationwide: bool,
    ) -> String {
        let threat_line: String = threats
            .iter()
            .map(|t| format!("{} {}", t.emoji(), t.label()))
            .collect::<Vec<_>>()
            .join(" + ");

        let prox_tag = if nationwide {
            "🟣 ВСЯ УКРАЇНА"
        } else {
            proximity.tag()
        };

        let mut out = String::new();

        // Urgency banner
        if urgent {
            out.push_str("🔁 ПОВТОРНО\n");
        }

        // Header
        if prox_tag.is_empty() {
            out.push_str(&format!("{threat_line}\n"));
        } else {
            out.push_str(&format!("{threat_line} · {prox_tag}\n"));
        }

        // Separator
        out.push_str("———\n");

        // Original message (trim to ~3200 chars to stay under TG limit)
        let trimmed = if text.len() > 3200 {
            &text[..3200]
        } else {
            text
        };
        out.push_str(trimmed);
        out.push('\n');

        // Source
        out.push_str(&format!("— 📡 {channel_title}"));
        out
    }

    fn format_negative_status(
        &self,
        proximity: Proximity,
        nationwide: bool,
        channel_title: &str,
        text: &str,
    ) -> String {
        let prox_tag = if nationwide {
            "🟣 ВСЯ УКРАЇНА"
        } else {
            proximity.tag()
        };
        let mut out = String::new();
        if prox_tag.is_empty() {
            out.push_str("ℹ️ Статус\n");
        } else {
            out.push_str(&format!("ℹ️ Статус · {prox_tag}\n"));
        }
        out.push_str("———\n");
        out.push_str(text);
        out.push_str(&format!("\n— 📡 {channel_title}"));
        out
    }
}

impl fmt::Display for AlertFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AlertFilter(oblast={:?}, city={:?}, district={:?}, dedup={}s, urgent_cd={}s, neg_status_cd={}s, fwd_all={})",
            self.location.oblast,
            self.location.city,
            self.location.district,
            self.dedup_window.as_secs(),
            self.urgent_same_channel_cooldown.as_secs(),
            self.negative_status_cooldown.as_secs(),
            self.forward_all_threats,
        )
    }
}

/// Kyiv-based user config with both UA and RU name forms.
pub fn kyiv_filter() -> AlertFilter {
    AlertFilter {
        location: LocationConfig {
            oblast: vec!["київськ".into(), "киевск".into()],
            city: vec![
                "київ".into(),
                "києв".into(), // UA declensions
                "киев".into(),
                "кiev".into(), // RU + transliteration
                "васильків".into(),
                "васильков".into(), // satellite city
            ],
            district: vec!["шевченківськ".into(), "шевченковск".into()],
        },
        dedup_window: Duration::from_secs(180),
        cache: HashMap::new(),
        channel_contexts: HashMap::new(),
        context_window: Duration::from_secs(300),
        urgent_same_channel_cooldown: Duration::from_secs(0),
        forward_all_threats: false,
        negative_status_state: HashMap::new(),
        negative_status_cooldown: Duration::from_secs(120),
    }
}

/// Kharkiv-based user config.
pub fn kharkiv_filter() -> AlertFilter {
    AlertFilter {
        location: LocationConfig {
            oblast: vec!["харківськ".into()],
            city: vec!["харків".into(), "харков".into()],
            district: vec!["київськ".into(), "шевченківськ".into()],
        },
        dedup_window: Duration::from_secs(180),
        cache: HashMap::new(),
        channel_contexts: HashMap::new(),
        context_window: Duration::from_secs(300),
        urgent_same_channel_cooldown: Duration::from_secs(0),
        forward_all_threats: false,
        negative_status_state: HashMap::new(),
        negative_status_cooldown: Duration::from_secs(120),
    }
}
