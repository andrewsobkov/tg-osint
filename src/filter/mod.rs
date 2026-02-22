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

// ───────────────────────────── Detection ─────────────────────────────────

/// Scan lowercased text and return the set of detected threat kinds.
/// More specific kinds suppress generic ones.
fn detect_threats(lower: &str) -> Vec<ThreatKind> {
    let mut found: Vec<ThreatKind> = Vec::new();

    for &(kind, stems) in THREAT_KEYWORDS {
        if stems.iter().any(|s| lower.contains(s)) {
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

    /// Return the highest proximity level that matches `lower` (already
    /// lowercased text).
    fn check(&self, lower: &str) -> Proximity {
        if self.district.iter().any(|kw| lower.contains(kw.as_str())) {
            return Proximity::District;
        }
        if self.city.iter().any(|kw| lower.contains(kw.as_str())) {
            return Proximity::City;
        }
        if self.oblast.iter().any(|kw| lower.contains(kw.as_str())) {
            return Proximity::Oblast;
        }
        Proximity::None
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
        // Check for target keywords
        let has_target = lower.contains("ціль")
            || lower.contains("цілі")
            || lower.contains("цілей")
            || lower.contains("цель")
            || (lower.contains("цели ") || lower.contains("цели\n"))
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
    /// `true` when the cached message itself was an urgency-tagged one
    /// ("повторно", "додатково", …).
    was_urgent: bool,
    /// Stable channel peer-id.  Used to distinguish a genuine
    /// same-channel re-alert from cross-channel echo spam.
    last_channel_id: i64,
}

/// Result of context-aware detection.
struct ContextDetection {
    threats: Vec<ThreatKind>,
    proximity: Proximity,
    nationwide: bool,
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
    /// When `true`, messages that contain threat keywords but do NOT match
    /// any user location are still forwarded (with `Proximity::None`).
    forward_all_threats: bool,
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
            forward_all_threats: forward_all,
        }
    }

    /// Evict expired entries (called lazily on each `process()`).
    fn evict(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, e| now.duration_since(e.sent_at) < self.dedup_window);
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

        let det = self.detect_with_context(channel_id, &lower, channel_title)?;

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

            // 2b. Location present but no threat → infer threat from context
            if proximity != Proximity::None && threats.is_empty() {
                if let Some(inferred) = context.infer_recent_threat() {
                    debug!("Inferred {inferred:?} from context (has location, no threat keyword)");
                    threats.push(inferred);
                }
            }

            // 2c. Urgent but no threat → infer threat from context
            if urgent && threats.is_empty() {
                if let Some(inferred) = context.infer_recent_threat() {
                    debug!("Inferred {inferred:?} from context (urgent, no threat keyword)");
                    threats.push(inferred);
                }
            }

            // 2d. Have threat but no location → infer location from context
            if !threats.is_empty() && proximity == Proximity::None && !nationwide {
                let ctx_prox = context.infer_location();
                if ctx_prox != Proximity::None {
                    debug!("Inferred location {ctx_prox:?} from context");
                    proximity = ctx_prox;
                }
            }

            // 2e. Urgent with no location → infer location from context
            if urgent && proximity == Proximity::None && !nationwide {
                let ctx_prox = context.infer_location();
                if ctx_prox != Proximity::None {
                    debug!("Inferred location {ctx_prox:?} from context (urgent)");
                    proximity = ctx_prox;
                }
            }

            // Store in context (even if we won't forward — seeds future inference)
            if !threats.is_empty() || proximity != Proximity::None {
                context.add(lower.to_owned(), threats.clone(), proximity);
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
            return Some(alert);
        }
        None
    }

    /// Determine proximity and nationwide status from lowercased text.
    fn resolve_location(&self, lower: &str, channel_title: &str) -> (Proximity, bool) {
        let lower_title = channel_title.to_lowercase();
        let combined = format!("{lower_title} {lower}");
        let nationwide = is_nationwide(lower);
        let proximity = if nationwide {
            let loc = self.location.check(&combined);
            if loc == Proximity::None {
                Proximity::Oblast
            } else {
                loc
            }
        } else {
            self.location.check(&combined)
        };
        (proximity, nationwide)
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

        if let Some(entry) = self.cache.get(&primary) {
            if proximity > entry.max_proximity {
                debug!(
                    "Dedup upgrade: {primary:?} {:?} → {proximity:?}",
                    entry.max_proximity
                );
            } else if urgent && !entry.was_urgent {
                debug!("Dedup: first urgent re-alert for {primary:?} – forwarding");
            } else if urgent && entry.last_channel_id == channel_id {
                debug!("Dedup: same-channel re-alert for {primary:?} – forwarding");
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
                was_urgent: urgent,
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
}

impl fmt::Display for AlertFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AlertFilter(oblast={:?}, city={:?}, district={:?}, dedup={}s, fwd_all={})",
            self.location.oblast,
            self.location.city,
            self.location.district,
            self.dedup_window.as_secs(),
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
        forward_all_threats: false,
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
        forward_all_threats: false,
    }
}
