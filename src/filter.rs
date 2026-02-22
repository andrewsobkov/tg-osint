//! Threat detection, location-based filtering, and smart deduplication
//! for Ukrainian air-raid / military alert channels.
//!
//! Supports **both Ukrainian and Russian** message text – most real-world
//! alert channels post in a mix of both.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use tracing::debug;

// ───────────────────────────── Threat kinds ──────────────────────────────

/// Broad threat categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatKind {
    Ballistic,
    Hypersonic, // Циркон / Zircon
    CruiseMissile,
    GuidedBomb, // КАБ / УМПБ / JDAM-ER
    Missile,    // generic / unspecified missile
    Shahed,
    ReconDrone,
    Aircraft,
    AllClear, // "відбій" / "отбой" – threat over
    Other,    // threat-sounding but unclassified
}

impl ThreatKind {
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Ballistic => "‼️🚀",
            Self::Hypersonic => "‼️⚡",
            Self::CruiseMissile => "🚀",
            Self::GuidedBomb => "💣",
            Self::Missile => "🚀",
            Self::Shahed => "🔺",
            Self::ReconDrone => "🛸",
            Self::Aircraft => "✈️",
            Self::AllClear => "✅",
            Self::Other => "⚠️",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Ballistic => "Балістика",
            Self::Hypersonic => "Гіперзвук",
            Self::CruiseMissile => "Крилата ракета",
            Self::GuidedBomb => "КАБ",
            Self::Missile => "Ракета",
            Self::Shahed => "Шахед / дрон",
            Self::ReconDrone => "Розвідувальний БПЛА",
            Self::Aircraft => "Авіація",
            Self::AllClear => "Відбій загрози",
            Self::Other => "Загроза",
        }
    }

    /// Priority used for dedup: a more specific kind wins over a generic one.
    fn specificity(&self) -> u8 {
        match self {
            Self::Ballistic => 4,
            Self::Hypersonic => 5,
            Self::CruiseMissile => 3,
            Self::GuidedBomb => 3,
            Self::Missile => 1,
            Self::Shahed => 3,
            Self::ReconDrone => 2,
            Self::Aircraft => 2,
            Self::AllClear => 6, // always most important
            Self::Other => 0,
        }
    }

    /// Stable English name used for LLM JSON interchange.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Ballistic => "Ballistic",
            Self::Hypersonic => "Hypersonic",
            Self::CruiseMissile => "CruiseMissile",
            Self::GuidedBomb => "GuidedBomb",
            Self::Missile => "Missile",
            Self::Shahed => "Shahed",
            Self::ReconDrone => "ReconDrone",
            Self::Aircraft => "Aircraft",
            Self::AllClear => "AllClear",
            Self::Other => "Other",
        }
    }

    /// Parse from the LLM's JSON string. Case-insensitive.
    pub fn from_variant_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ballistic" => Some(Self::Ballistic),
            "hypersonic" => Some(Self::Hypersonic),
            "cruisemissile" | "cruise_missile" => Some(Self::CruiseMissile),
            "guidedbomb" | "guided_bomb" | "kab" => Some(Self::GuidedBomb),
            "missile" => Some(Self::Missile),
            "shahed" => Some(Self::Shahed),
            "recondrone" | "recon_drone" => Some(Self::ReconDrone),
            "aircraft" => Some(Self::Aircraft),
            "allclear" | "all_clear" => Some(Self::AllClear),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

/// Keyword stems for each threat kind.  **Order matters** – more specific
/// variants must appear before generic ones so that the first match wins
/// during detection.
///
/// Each entry contains **both Ukrainian (UA) and Russian (RU)** stems.
const THREAT_KEYWORDS: &[(ThreatKind, &[&str])] = &[
    // ── All clear ──────────────────────────────────────────────────────
    (
        ThreatKind::AllClear,
        &[
            // UA
            "відбій", // відбій тривоги
            "загроза минула",
            "чисте небо",
            // RU
            "отбой", // отбой тревоги
            "угроза миновала",
            "чистое небо",
        ],
    ),
    // ── Hypersonic ─────────────────────────────────────────────────────
    (
        ThreatKind::Hypersonic,
        &[
            // UA
            "гіперзвук", // гіперзвукова, гіперзвуковий
            "циркон",
            "орєшнік", // Oreshnik hypersonic MRBM
            // RU
            "гиперзвук", // гиперзвуковая, гиперзвуковой
            "циркон",    // same stem
            "орешник",   // RU spelling
            // EN / transliteration
            "zircon",
            "tsirkon",
            "oreshnik",
        ],
    ),
    // ── Ballistic ──────────────────────────────────────────────────────
    (
        ThreatKind::Ballistic,
        &[
            // UA
            "балістик",  // балістика, балістику …
            "балістичн", // балістична, балістичний …
            "іскандер",
            "кінжал",
            "точка-у",
            "брсд",             // балістична ракета середньої дальності
            "міжконтинентальн", // міжконтинентальна
            // RU
            "баллистик", // баллистика, баллистики …
            "баллістик", // mixed spelling
            "искандер",
            "кинжал",
            "точка-у",
            "брсд",             // same abbreviation in RU
            "межконтинентальн", // межконтинентальная
            // missile names / designations
            "iskander",
            "кедр", // Kedr missile
            "kedr",
            "рс-26",
            "rs-26", // RS-26 Rubezh
            "рубіж", // UA: Rubizh
            "рубеж", // RU: Rubezh
            "rubezh",
            "кн-23",
            "kn-23", // North Korean
            "кн-25",
            "kn-25",
            "фатех",
            "fateh",               // Fateh-110/360
            "hwasong",             // North Korean Hwasong
            "середньої дальності", // UA: medium range
            "средней дальности",   // RU: medium range
        ],
    ),
    // ── Cruise missile ─────────────────────────────────────────────────
    (
        ThreatKind::CruiseMissile,
        &[
            // UA
            "крилат", // крилата, крилатих …
            "калібр",
            // RU
            "крылат", // крылатая, крылатых …
            "калибр",
            // model names – Cyrillic variants
            "х-101",
            "х-555",
            "х-22",
            "х-59",
            "х-69",
            "х-35",
            "х-31",
            "х-55", // older cruise missile
            // model names – Latin variants
            "x-101",
            "x-555",
            "x-22",
            "x-59",
            "x-69",
            "x-35",
            "x-31",
            "x-55",
            // foreign
            "томагавк",
            "tomahawk", // sometimes referenced for comparison
        ],
    ),
    // ── Guided aerial bomb (КАБ / УМПБ) ───────────────────────────────
    (
        ThreatKind::GuidedBomb,
        &[
            // UA
            "керован",  // керована авіабомба, керованих …
            "авіабомб", // авіабомба, авіабомб …
            "авіаційн бомб",
            "плануюч", // плануюча бомба
            // RU
            "управляем", // управляемая бомба
            "авиабомб",  // авиабомба …
            "планирующ", // планирующая бомба
            // abbreviations / model names
            "каб-500",
            "каб-1500",
            "каб-250",
            "каб ",  // "КАБ " with trailing space
            "каб,",  // "КАБ," punctuation variant
            "каб.",  // "КАБ." end of sentence
            "каб\n", // "КАБ" at end of line
            "умпб",  // УМПБ (unified modular glide bomb)
            "умпк",  // УМПК (glide kit)
            "jdam",
            "фаб-500",
            "фаб-1500",
            "фаб-250",
            "фаб-3000",
            "фаб ", // "ФАБ " with trailing space
            "фаб,",
            "фаб.",
            "фаб\n",
        ],
    ),
    // ── Shahed / attack drone ──────────────────────────────────────────
    (
        ThreatKind::Shahed,
        &[
            "шахед",
            "shahed",
            "герань",
            "geran",
            "мопед",       // slang (UA + RU)
            "газонокосил", // "газонокосилка" – slang for Shahed (lawnmower)
            "ударн",       // UA: ударний / RU: ударный (same stem)
            "бпла",
            "дрон-камікадзе", // UA
            "дрон-камикадзе", // RU
            "камікадзе",      // can stand alone
            "камикадзе",
            "безпілотник", // UA: generic UAV
            "беспилотник", // RU: generic UAV
            "mohajer",     // Iranian Mohajer
            "мохаджер",
            "дрон ",  // "дрон " (with space to reduce false positives)
            "дронів", // UA genitive plural
            "дронов", // RU genitive plural
            "махаон", // newer Russian drone names
        ],
    ),
    // ── Recon drone ────────────────────────────────────────────────────
    (
        ThreatKind::ReconDrone,
        &[
            "розвідувальн",   // UA
            "разведывательн", // RU
            "орлан",
            "zala",
            "supercam",
            "ланцет",
            "елерон",    // UA: БПЛА Елерон
            "элерон",    // RU
            "картограф", // drone name
            "фурія",     // UA Fury drone
            "фурия",
        ],
    ),
    // ── Aircraft ───────────────────────────────────────────────────────
    (
        ThreatKind::Aircraft,
        &[
            // UA
            "авіаці",            // авіація, авіаційний …
            "стратегічн авіаці", // стратегічна авіація
            "тактичн авіаці",    // тактична авіація
            "зліт",              // зліт (takeoff of bombers = imminent threat)
            // RU
            "авиаци", // авиация …
            "стратегическ авиаци",
            "тактическ авиаци",
            "взлёт", // takeoff
            "взлет", // alternate
            // aircraft types – Cyrillic
            "ту-95",
            "ту-160",
            "ту-22",
            "міг-31",
            "міг-29",
            "миг-31",
            "миг-29",
            "су-57",
            "су-35",
            "су-34",
            "су-30",
            "су-25",
            "су-24",
            // AWACS / tanker / transport (launch-related)
            "а-50",
            "a-50",
            "іл-76",
            "ил-76",
        ],
    ),
    // ── Generic missile (AFTER more specific kinds) ────────────────────
    //
    // CAREFUL: stems here must not be too greedy. Avoid short stems that
    // appear in non-alert analytical text (e.g. "пускові зони",
    // "у напрямку Кілія", "цілком спокійно").
    (
        ThreatKind::Missile,
        &[
            "ракет",  // UA+RU: ракета, ракети, ракеты, ракетна …
            "запуск", // запуск ракет (more specific than "пуск")
            // UA target forms — safe because ь≠к so "ціль" ⊄ "цілком"
            "ціль",  // ціль на Київ
            "цілі",  // 2 цілі на Київ
            "цілей", // кількість цілей
            // RU target forms — "цель" ⊄ "целом" (ь≠о), but
            // "цели" ⊂ "целиком" so we need trailing space/newline variants.
            "цель",  // цель на Киев (ь≠о safe vs целом)
            "цели ", // 3 цели на Днепр
            "цели\n",
            "целей", // количество целей
            // heading / direction phrases (multi-word to avoid false positives)
            // specific systems
            "с-300",
            "s-300",
            "с-400",
            "s-400",
            "зенітн ракет", // UA: зенітна ракета (used as ballistic)
            "зенитн ракет", // RU
        ],
    ),
    // ── Other threat signals (catch-all) ───────────────────────────────
    (
        ThreatKind::Other,
        &[
            // UA
            "загроз", // загроза, загрози …
            "небезпек",
            "тривог", // тривога, тривоги
            "обстріл",
            "вибух",
            "прильот",
            "влучанн",       // влучання
            "уламк",         // уламки (debris / intercept fragments)
            "укриття",       // shelter – "терміново в укриття!"
            "укрытие",       // RU: shelter
            "пожеж",         // пожежа (fire after impact)
            "руйнуванн",     // руйнування (destruction)
            "зруйнов",       // зруйновано (destroyed)
            "інфраструктур", // infrastructure hit
            "кассетн",       // касетна / кассетная (cluster munition)
            "касетн",        // UA spelling
            // RU
            "угроз", // угроза, угрозы
            "опасност",
            "тревог", // тревога
            "обстрел",
            "взрыв",
            "прилёт",
            "прилет",
            "попадани",  // попадание
            "осколк",    // осколки (fragments)
            "пожар",     // fire
            "разрушени", // разрушение (destruction)
            "инфраструктур",
            // mixed
            "громко", // "Будет громко!" – expect explosions
        ],
    ),
];

// ───────────────────────── Urgency keywords ──────────────────────────────

/// Keywords that signal "this is a repeated / additional wave" and should
/// bypass dedup (once per source channel – see `DedupEntry::last_channel_id`).
const URGENCY_KEYWORDS: &[&str] = &[
    // UA
    "повторно",  // repeated
    "додатково", // additionally
    "ще ціл",    // ще ціль / ще цілі – more targets
    "нові ціл",  // нові цілі
    "нова хвил", // нова хвиля (new wave)
    "увага!",    // УВАГА! – attention
    "терміново", // urgently
    "негайно",   // immediately (e.g. "негайно в укриття!")
    // RU
    "повторно",
    "дополнительно",
    "ещё",
    "еще",
    "новая волна", // new wave
    "внимание!",   // ВНИМАНИЕ!
    "срочно",      // urgently
    "немедленно",  // immediately
];

/// Returns `true` when the message contains an urgency keyword that should
/// bypass dedup.
fn is_urgent(lower: &str) -> bool {
    URGENCY_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

// ───────────────────── Nationwide alert detection ────────────────────────

/// Phrases that mean "the entire country" — these alerts are relevant to
/// everyone regardless of their configured oblast/city/district.
const NATIONWIDE_KEYWORDS: &[&str] = &[
    // UA — require explicit "України" / "Україні" to avoid regional FPs
    "по всій території україни",
    "всю територію україни",
    "всієї території україни",
    "по всій україні",
    "всій україні",
    "по всій країні", // sometimes used instead of "Україні"
    // RU — require explicit "Украины" / "Украине"
    "по всей территории украины",
    "всю территорию украины",
    "всей территории украины",
    "по всей украине",
    "всей украине",
    "по всей стране",
];

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

/// Stateful filter: detects threats, checks location, deduplicates.
pub struct AlertFilter {
    location: LocationConfig,
    dedup_window: Duration,
    cache: HashMap<ThreatKind, DedupEntry>,
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
    /// | `FORWARD_ALL_THREATS`  | `false` | Forward threats outside your area too   |
    pub fn from_env() -> Self {
        let location = LocationConfig::from_env();
        let dedup_secs: u64 = std::env::var("DEDUP_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(180);
        let forward_all: bool = std::env::var("FORWARD_ALL_THREATS")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            location,
            dedup_window: Duration::from_secs(dedup_secs),
            cache: HashMap::new(),
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
        let lower_title = channel_title.to_lowercase();
        let combined = format!("{lower_title} {lower}");

        // 1. Detect threats
        let threats = detect_threats(&lower);
        if threats.is_empty() {
            debug!("No threat keywords found – skipping");
            return None;
        }

        // 1a. AllClear is always forwarded (no location / dedup gate).
        if threats.contains(&ThreatKind::AllClear) && threats.len() == 1 {
            let alert = self.format(&threats, Proximity::None, channel_title, text, false, false);
            // Clear the dedup cache – the threat wave is over.
            self.cache.clear();
            return Some(alert);
        }

        // 2. Check location / nationwide
        let nationwide = is_nationwide(&lower);
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

        if proximity == Proximity::None && !self.forward_all_threats {
            debug!("Threat detected but no location match – skipping");
            return None;
        }

        // 3. Check urgency ("повторно", "додатково", …)
        let urgent = is_urgent(&lower);

        // 4. Dedup
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

        // Update cache.
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

        // 5. Format
        let alert = self.format(&threats, proximity, channel_title, text, urgent, nationwide);
        Some(alert)
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

        // Quick exit: no keywords at all.
        let kw_threats = detect_threats(&lower);
        if kw_threats.is_empty() {
            debug!("No threat keywords found – skipping");
            return None;
        }

        // AllClear fast-path (no LLM needed).
        if kw_threats.contains(&ThreatKind::AllClear) && kw_threats.len() == 1 {
            let alert = self.format(
                &kw_threats,
                Proximity::None,
                channel_title,
                text,
                false,
                false,
            );
            self.cache.clear();
            return Some(alert);
        }

        // Location / nationwide.
        let lower_title = channel_title.to_lowercase();
        let combined = format!("{lower_title} {lower}");
        let nationwide = is_nationwide(&lower);
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

        if proximity == Proximity::None && !self.forward_all_threats {
            debug!("Threat detected but no location match – skipping");
            return None;
        }

        // ── LLM verification (async) ──
        let threats = if llm.is_enabled() {
            let verified = llm.verify(text, &kw_threats, proximity, nationwide).await;
            if verified.is_empty() {
                debug!("LLM says not an active alert – suppressing");
                return None;
            }
            verified
        } else {
            kw_threats
        };

        // Urgency + dedup (same as process_with_id).
        let urgent = is_urgent(&lower);
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

        let alert = self.format(&threats, proximity, channel_title, text, urgent, nationwide);
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

// ─────────────────────────────── Tests ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Kyiv-based user config with both UA and RU name forms.
    fn kyiv_filter() -> AlertFilter {
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
            forward_all_threats: false,
        }
    }

    /// Kharkiv-based user config.
    fn kharkiv_filter() -> AlertFilter {
        AlertFilter {
            location: LocationConfig {
                oblast: vec!["харківськ".into()],
                city: vec!["харків".into(), "харков".into()],
                district: vec!["київськ".into(), "шевченківськ".into()],
            },
            dedup_window: Duration::from_secs(180),
            cache: HashMap::new(),
            forward_all_threats: false,
        }
    }

    // ── Threat detection (UA) ──

    #[test]
    fn detects_ballistic_ua() {
        let threats = detect_threats("увага! балістична загроза з півдня");
        assert!(threats.contains(&ThreatKind::Ballistic));
        assert!(!threats.contains(&ThreatKind::Missile));
    }

    #[test]
    fn detects_ballistic_ua_noun() {
        let threats = detect_threats("загроза балістики з брянська");
        assert!(threats.contains(&ThreatKind::Ballistic));
    }

    #[test]
    fn detects_shahed_ua() {
        let threats = detect_threats("шахеди в напрямку харкова");
        assert!(threats.contains(&ThreatKind::Shahed));
    }

    #[test]
    fn detects_generic_missile_ua() {
        let threats = detect_threats("пуск ракети з півдня");
        assert!(threats.contains(&ThreatKind::Missile));
    }

    #[test]
    fn detects_target_ua() {
        let threats = detect_threats("ще ціль на київ");
        assert!(threats.contains(&ThreatKind::Missile));
        let threats2 = detect_threats("2 цілі на київ");
        assert!(threats2.contains(&ThreatKind::Missile));
    }

    #[test]
    fn detects_iskander_ua() {
        let threats = detect_threats("можливі пуски ракет типу «іскандер-м/кн-23/с-300");
        assert!(threats.contains(&ThreatKind::Ballistic));
        assert!(!threats.contains(&ThreatKind::Missile));
    }

    // ── Threat detection (RU) ──

    #[test]
    fn detects_ballistic_ru() {
        let threats = detect_threats("баллистика на киев!");
        assert!(threats.contains(&ThreatKind::Ballistic));
        assert!(!threats.contains(&ThreatKind::Missile));
    }

    #[test]
    fn detects_ballistic_ru_plural() {
        let threats = detect_threats("4 баллистики на днепр");
        assert!(threats.contains(&ThreatKind::Ballistic));
    }

    #[test]
    fn detects_moped_ru() {
        let threats = detect_threats("8 мопедов летят на днепр");
        assert!(threats.contains(&ThreatKind::Shahed));
    }

    #[test]
    fn detects_missile_ru() {
        let threats = detect_threats("2 ракеты на киев");
        assert!(threats.contains(&ThreatKind::Missile));
    }

    #[test]
    fn detects_mixed_ru() {
        let threats = detect_threats("10 мопедов и 4 баллистики на днепр");
        assert!(threats.contains(&ThreatKind::Shahed));
        assert!(threats.contains(&ThreatKind::Ballistic));
        assert!(!threats.contains(&ThreatKind::Missile));
    }

    // ── New categories: Hypersonic ──

    #[test]
    fn detects_hypersonic_ua() {
        let threats = detect_threats("гіперзвукова ракета з півдня");
        assert!(threats.contains(&ThreatKind::Hypersonic));
        assert!(!threats.contains(&ThreatKind::Missile)); // suppressed
    }

    #[test]
    fn detects_zircon_ru() {
        let threats = detect_threats("пуск циркона з акваторії чорного моря");
        assert!(threats.contains(&ThreatKind::Hypersonic));
    }

    // ── New categories: Guided bomb (КАБ) ──

    #[test]
    fn detects_kab_ua() {
        let threats = detect_threats("скидання каб-500 по позиціях");
        assert!(threats.contains(&ThreatKind::GuidedBomb));
    }

    #[test]
    fn detects_fab_ru() {
        let threats = detect_threats("сброс фаб-500 по харькову");
        assert!(threats.contains(&ThreatKind::GuidedBomb));
    }

    #[test]
    fn detects_umpb() {
        let threats = detect_threats("умпб в напрямку сумської області");
        assert!(threats.contains(&ThreatKind::GuidedBomb));
    }

    #[test]
    fn detects_guided_bomb_ua_long() {
        let threats = detect_threats("загроза застосування керованих авіабомб");
        assert!(threats.contains(&ThreatKind::GuidedBomb));
    }

    // ── Expanded Shahed keywords ──

    #[test]
    fn detects_bezpilotnik_ua() {
        let threats = detect_threats("безпілотники в напрямку києва");
        assert!(threats.contains(&ThreatKind::Shahed));
    }

    #[test]
    fn detects_gazonokosilka() {
        // slang "газонокосилка" (lawnmower) = Shahed
        let threats = detect_threats("газонокосилки на підльоті до київської області");
        assert!(threats.contains(&ThreatKind::Shahed));
    }

    #[test]
    fn detects_kamikaze_drone() {
        let threats = detect_threats("дрон-камікадзе над полтавською областю");
        assert!(threats.contains(&ThreatKind::Shahed));
    }

    // ── Expanded Aircraft keywords ──

    #[test]
    fn detects_strategic_aviation_ua() {
        let threats = detect_threats("зліт стратегічної авіації з аеродрому енгельс");
        assert!(threats.contains(&ThreatKind::Aircraft));
    }

    #[test]
    fn detects_takeoff_ru() {
        let threats = detect_threats("взлёт ту-95 с аэродрома энгельс");
        assert!(threats.contains(&ThreatKind::Aircraft));
    }

    #[test]
    fn detects_su57() {
        let threats = detect_threats("су-57 в повітрі");
        assert!(threats.contains(&ThreatKind::Aircraft));
    }

    // ── Expanded generic missile ──

    #[test]
    fn detects_launch_ru() {
        let threats = detect_threats("запуск ракет з акваторії");
        assert!(threats.contains(&ThreatKind::Missile));
    }

    #[test]
    fn detects_heading_to_ua() {
        let threats = detect_threats("ракети курсом на захід");
        assert!(threats.contains(&ThreatKind::Missile));
    }

    // ── Expanded Other (catch-all) ──

    #[test]
    fn detects_debris_ua() {
        let threats = detect_threats("падіння уламків у шевченківському районі");
        assert!(threats.contains(&ThreatKind::Other));
    }

    #[test]
    fn detects_shelter_ua() {
        let threats = detect_threats("терміново в укриття!");
        assert!(threats.contains(&ThreatKind::Other));
    }

    #[test]
    fn detects_cluster_munition_ru() {
        let threats = detect_threats("кассетные боеприпасы по области");
        assert!(threats.contains(&ThreatKind::Other));
    }

    // ── False positive regression tests ──

    #[test]
    fn no_false_positive_analytical_report() {
        // This is a calm situation report from Aeris Rimor – NOT an active
        // alert. Previously "пускові" triggered Missile via "пуск" stem.
        let threats = detect_threats(
            "проявів з того моменту особливо помічено не було. \
             очікуваними є до 2:30. бо в цей період крайній відрізок \
             коли може відбутись виліт са з оленья, аби встигнути \
             на пускові зони згідно поточної тактики застосування. \
             також нагадую, що у випадку атак на центр країни, ворог \
             може починати основну фазу вже вночі. пильнуємо ще \
             щонайменше до 2 годин ночі. але поки все відносно спокійно.",
        );
        // Should NOT detect any threat – this is informational text.
        assert!(
            threats.is_empty(),
            "False positive on analytical report: {threats:?}"
        );
    }

    #[test]
    fn no_false_missile_on_napryamku() {
        // "у напрямку Кілія" is a direction, not a missile indicator.
        // Only Shahed (via "бпла") should match.
        let threats = detect_threats("група ~10х бпла у напрямку кілія/ізмаїл, одещина");
        assert!(threats.contains(&ThreatKind::Shahed));
        assert!(
            !threats.contains(&ThreatKind::Missile),
            "\"напрямку\" should not trigger Missile: {threats:?}"
        );
    }

    #[test]
    fn no_false_missile_on_puskovi() {
        // "пускові зони" is analytical, not an active launch.
        let threats = detect_threats("встигнути на пускові зони");
        assert!(
            threats.is_empty(),
            "\"пускові\" should not trigger: {threats:?}"
        );
    }

    #[test]
    fn no_false_missile_on_tsilkom() {
        // "цілком спокійно" = "completely calm" – not a target/missile.
        let threats = detect_threats("цілком спокійно, загрози немає");
        assert!(
            !threats.contains(&ThreatKind::Missile),
            "\"цілком\" should not trigger Missile: {threats:?}"
        );
    }

    #[test]
    fn no_false_missile_on_tseliy() {
        // "в целом" = "in general" – not a target/missile.
        let threats = detect_threats("в целом ситуация спокойная");
        assert!(
            !threats.contains(&ThreatKind::Missile),
            "\"целом\" should not trigger Missile: {threats:?}"
        );
    }

    #[test]
    fn no_false_missile_on_tselikom() {
        // "целиком" = "completely" – not a target/missile.
        let threats = detect_threats("целиком уничтожен объект");
        assert!(
            !threats.contains(&ThreatKind::Missile),
            "\"целиком\" should not trigger Missile: {threats:?}"
        );
    }

    #[test]
    fn still_detects_real_targets() {
        // Real target messages must still match.
        let t1 = detect_threats("ціль на київ!");
        assert!(t1.contains(&ThreatKind::Missile), "\"ціль на\" must match");

        let t2 = detect_threats("2 цілі на захід");
        assert!(t2.contains(&ThreatKind::Missile), "\"цілі на\" must match");

        let t3 = detect_threats("цель на киев");
        assert!(t3.contains(&ThreatKind::Missile), "\"цель на\" must match");

        let t4 = detect_threats("3 цели на днепр");
        assert!(t4.contains(&ThreatKind::Missile), "\"цели \" must match");

        // End-of-string / end-of-line
        let t5 = detect_threats("нова ціль");
        assert!(
            t5.contains(&ThreatKind::Missile),
            "\"ціль\" at end must match"
        );

        let t6 = detect_threats("ще одна ціль\nна захід");
        assert!(t6.contains(&ThreatKind::Missile), "\"ціль\\n\" must match");
    }

    #[test]
    fn process_skips_analytical_report() {
        // Full integration test: the Aeris Rimor message should be
        // completely skipped (no threat keywords → None).
        let mut filter = kyiv_filter();
        let r = filter.process(
            "Aeris Rimor",
            "Проявів з того моменту особливо помічено не було.\n\
             Очікуваними є до 2:30. Бо в цей період крайній відрізок \
             коли може відбутись виліт СА з Оленья, аби встигнути \
             на пускові зони згідно поточної тактики застосування.\n\
             Також нагадую, що у випадку атак на центр країни, ворог \
             може починати основну фазу вже вночі.\n\
             Пильнуємо ще щонайменше до 2 годин ночі. Але поки все \
             відносно спокійно. Не рахуючи схід та Одещину.",
        );
        assert!(r.is_none(), "Analytical report should NOT be forwarded");
    }

    #[test]
    fn process_drone_no_missile_tag() {
        // The BpLA message should only get Shahed tag, NOT Missile.
        let mut filter = kyiv_filter();
        // Use a filter that matches Одеська for test purposes
        filter.forward_all_threats = true;
        let r = filter.process(
            "monitor",
            "⚠️ Група ~10х БпЛА у напрямку Кілія/Ізмаїл, Одещина",
        );
        assert!(r.is_some());
        let text = r.unwrap();
        assert!(text.contains("Шахед"), "Should detect Shahed");
        assert!(
            !text.contains("Ракета"),
            "Should NOT detect Missile from напрямку"
        );
    }

    #[test]
    fn detects_all_clear_ua() {
        let threats = detect_threats("відбій тривоги");
        assert!(threats.contains(&ThreatKind::AllClear));
    }

    #[test]
    fn detects_all_clear_ru() {
        let threats = detect_threats("отбой тревоги");
        assert!(threats.contains(&ThreatKind::AllClear));
    }

    #[test]
    fn detects_all_clear_ua_sky() {
        let threats = detect_threats("чисте небо над київською областю");
        assert!(threats.contains(&ThreatKind::AllClear));
    }

    #[test]
    fn detects_all_clear_ru_sky() {
        let threats = detect_threats("чистое небо, угроза миновала");
        assert!(threats.contains(&ThreatKind::AllClear));
    }

    // ── Urgency (expanded) ──

    #[test]
    fn urgency_povtorno_ru() {
        assert!(is_urgent("повторно баллистика на киев!"));
    }

    #[test]
    fn urgency_povtorno_ua() {
        assert!(is_urgent("повторно балістика на київ!"));
    }

    #[test]
    fn urgency_additionally_ua() {
        assert!(is_urgent("додатково загроза балістики з таганрога"));
    }

    #[test]
    fn urgency_more_targets() {
        assert!(is_urgent("ще ціль на київ"));
    }

    #[test]
    fn urgency_new_wave_ua() {
        assert!(is_urgent("нова хвиля шахедів"));
    }

    #[test]
    fn urgency_new_wave_ru() {
        assert!(is_urgent("новая волна дронов"));
    }

    #[test]
    fn urgency_terminovo_ua() {
        assert!(is_urgent("терміново в укриття!"));
    }

    #[test]
    fn urgency_srochno_ru() {
        assert!(is_urgent("срочно в укрытие!"));
    }

    #[test]
    fn no_urgency_in_normal_msg() {
        assert!(!is_urgent("баллистика на киев!"));
    }

    // ── Proximity ──

    #[test]
    fn proximity_city_ru() {
        let filter = kyiv_filter();
        let p = filter.location.check("2 ракеты на киев");
        assert_eq!(p, Proximity::City);
    }

    #[test]
    fn proximity_city_ua() {
        let filter = kyiv_filter();
        let p = filter.location.check("ще ціль на київ");
        assert_eq!(p, Proximity::City);
    }

    #[test]
    fn proximity_satellite_city() {
        let filter = kyiv_filter();
        let p = filter
            .location
            .check("баллистика на киев/васильков !!! 2 ракеты");
        assert_eq!(p, Proximity::City);
    }

    #[test]
    fn proximity_district() {
        let filter = kharkiv_filter();
        let p = filter.location.check("вибухи у київському районі харкова");
        assert_eq!(p, Proximity::District);
    }

    #[test]
    fn proximity_city_kharkiv() {
        let filter = kharkiv_filter();
        let p = filter.location.check("дрони в напрямку харкова");
        assert_eq!(p, Proximity::City);
    }

    #[test]
    fn proximity_oblast_isolated() {
        // Test oblast with a config where city doesn't collide with oblast root
        let loc = LocationConfig {
            oblast: vec!["харківськ".into()],
            city: vec!["ізюм".into()],
            district: vec![],
        };
        let p = loc.check("загроза для харківської області");
        assert_eq!(p, Proximity::Oblast);
    }

    // ── Integration: process() ──

    #[test]
    fn no_match_skipped() {
        let mut filter = kyiv_filter();
        let result = filter.process("Канал", "баллистика на одессу");
        assert!(result.is_none());
    }

    #[test]
    fn matching_message_forwarded() {
        let mut filter = kyiv_filter();
        let result = filter.process("Alerts", "баллистика на киев!");
        assert!(result.is_some());
    }

    #[test]
    fn dedup_suppresses_duplicate() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "2 ракеты на киев");
        assert!(r1.is_some());
        // Same threat kind + same proximity → suppressed
        let r2 = filter.process("Ch2", "ракеты летят на киев");
        assert!(r2.is_none());
    }

    #[test]
    fn dedup_allows_proximity_upgrade() {
        let mut filter = kharkiv_filter();
        let r1 = filter.process("Ch1", "шахеди увійшли в харківську область");
        assert!(r1.is_some());
        let r2 = filter.process("Ch2", "шахеди над київським районом харкова");
        assert!(r2.is_some()); // upgrade Oblast → District
    }

    #[test]
    fn different_threat_kinds_not_deduped() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "мопеды летят к киеву");
        assert!(r1.is_some());
        let r2 = filter.process("Ch1", "баллистика на киев!");
        assert!(r2.is_some());
    }

    #[test]
    fn repeated_bypasses_dedup() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "баллистика на киев!");
        assert!(r1.is_some());
        // Normally same threat+city would be suppressed, but "повторно" bypasses dedup.
        let r2 = filter.process("Ch1", "повторно баллистика на киев!");
        assert!(r2.is_some());
        assert!(r2.unwrap().contains("ПОВТОРНО"));
    }

    #[test]
    fn repeated_missile_ru() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "2 ракеты на киев");
        assert!(r1.is_some());
        let r2 = filter.process("Ch2", "повторно 2 ракеты на киев !");
        assert!(r2.is_some());
    }

    #[test]
    fn additionally_bypasses_dedup() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "загроза балістики з брянська на київ");
        assert!(r1.is_some());
        let r2 = filter.process("Ch2", "додатково загроза балістики з таганрога на київ");
        assert!(r2.is_some());
    }

    #[test]
    fn all_clear_always_forwarded() {
        let mut filter = kyiv_filter();
        // No prior threat needed; all-clear is always forwarded.
        let r = filter.process("Ch1", "відбій тривоги");
        assert!(r.is_some());
        assert!(r.unwrap().contains("Відбій"));
    }

    #[test]
    fn all_clear_clears_dedup_cache() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "баллистика на киев!");
        assert!(r1.is_some());
        // All-clear should clear the cache
        let r2 = filter.process("Ch1", "відбій тривоги");
        assert!(r2.is_some());
        // Same threat as before should now go through (cache cleared)
        let r3 = filter.process("Ch1", "баллистика на киев!");
        assert!(r3.is_some());
    }

    // ── Verify sample messages from messages_to_react.txt ──

    #[test]
    fn sample_mopeds_to_kyiv() {
        let mut filter = kyiv_filter();
        let r = filter.process("Ch", "12 мопедов летят к киеву");
        assert!(r.is_some());
    }

    #[test]
    fn sample_ballistic_vasylkiv() {
        let mut filter = kyiv_filter();
        let r = filter.process("Ch", "баллистика на киев/васильков !!! 2 ракеты");
        assert!(r.is_some());
    }

    #[test]
    fn sample_2_targets_on_kyiv() {
        let mut filter = kyiv_filter();
        let r = filter.process("Ch", "2 цілі на київ");
        assert!(r.is_some());
    }

    #[test]
    fn sample_repeated_ballistic_ua() {
        let mut filter = kyiv_filter();
        let _ = filter.process("Ch1", "балістика на київ");
        // "Повторно" should bypass dedup
        let r2 = filter.process("Ch2", "повторно балістика на київ!");
        assert!(r2.is_some());
    }

    // ── Cross-channel urgent spam prevention ──

    #[test]
    fn full_scenario_6_steps() {
        let mut filter = kyiv_filter();

        // 1. Ch1: normal → forwarded (first alert)
        let r1 = filter.process("Ch1", "баллистика на киев!");
        assert!(r1.is_some());

        // 2. Ch2: normal duplicate → suppressed (dedup)
        let r2 = filter.process("Ch2", "баллистика на киев");
        assert!(r2.is_none());

        // 3. Ch3: "повторно" → forwarded (first re-alert)
        let r3 = filter.process("Ch3", "повторно баллистика на киев!");
        assert!(r3.is_some());
        assert!(r3.unwrap().contains("ПОВТОРНО"));

        // 4. Ch4: "повторно" from different channel → suppressed (echo)
        let r4 = filter.process("Ch4", "повторно баллистика на киев!!!");
        assert!(r4.is_none());

        // 5. Ch5: normal → suppressed
        let r5 = filter.process("Ch5", "баллистика на київ/васильков");
        assert!(r5.is_none());

        // 6. Ch3: same channel "повторно" again → forwarded (genuine new wave)
        let r6 = filter.process("Ch3", "повторно баллистика на киев!");
        assert!(r6.is_some());
    }

    #[test]
    fn non_urgent_after_urgent_still_suppressed() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "баллистика на киев!");
        assert!(r1.is_some());
        let r2 = filter.process("Ch2", "повторно баллистика на киев!");
        assert!(r2.is_some());
        // Non-urgent from a 3rd channel → suppressed
        let r3 = filter.process("Ch3", "баллистика на киев!");
        assert!(r3.is_none());
    }

    #[test]
    fn urgent_proximity_upgrade_still_works() {
        let mut filter = kharkiv_filter();
        // City-level alert
        let r1 = filter.process("Ch1", "шахеди увійшли в харківську область");
        assert!(r1.is_some());
        // Urgent + proximity upgrade → goes through
        let r2 = filter.process("Ch2", "повторно шахеди над київським районом харкова");
        assert!(r2.is_some());
    }

    // ── MRBM / Oreshnik / Kedr / БРСД ──

    #[test]
    fn detects_brsd_ua() {
        let threats = detect_threats(
            "загроза застосування балістики середньої дальності (брсд) по всій території україни",
        );
        assert!(threats.contains(&ThreatKind::Ballistic));
    }

    #[test]
    fn detects_oreshnik_ua() {
        let threats = detect_threats("імовірний пуск ракети кедр/орєшнік (п/п рс-26)");
        assert!(threats.contains(&ThreatKind::Ballistic)); // кедр, рс-26
        assert!(threats.contains(&ThreatKind::Hypersonic)); // орєшнік
    }

    #[test]
    fn detects_oreshnik_ru() {
        let threats = detect_threats("орешник по всей территории украины!");
        assert!(threats.contains(&ThreatKind::Hypersonic));
    }

    #[test]
    fn detects_kedr() {
        let threats = detect_threats("запуск ракети кедр з астраханської області");
        assert!(threats.contains(&ThreatKind::Ballistic));
    }

    #[test]
    fn detects_rs26() {
        let threats = detect_threats("рс-26 рубіж запущено");
        assert!(threats.contains(&ThreatKind::Ballistic));
    }

    #[test]
    fn detects_medium_range_ru() {
        let threats = detect_threats("баллистическая ракета средней дальности");
        assert!(threats.contains(&ThreatKind::Ballistic));
    }

    #[test]
    fn detects_icbm_ua() {
        let threats = detect_threats("загроза міжконтинентальної балістичної ракети");
        assert!(threats.contains(&ThreatKind::Ballistic));
    }

    // ── Nationwide detection ──

    #[test]
    fn nationwide_ua() {
        assert!(is_nationwide("загроза по всій території україни"));
    }

    #[test]
    fn nationwide_ru() {
        assert!(is_nationwide("угроза по всей территории украины"));
    }

    #[test]
    fn not_nationwide_normal() {
        assert!(!is_nationwide("баллистика на киев!"));
    }

    #[test]
    fn not_nationwide_regional_territory() {
        // "по всій території області" should NOT match —
        // it's regional, not nationwide.
        assert!(!is_nationwide("по всій території харківської області"));
        assert!(!is_nationwide("по всей территории области"));
    }

    #[test]
    fn nationwide_bypasses_location_filter() {
        let mut filter = kharkiv_filter();
        // This message has no Kharkiv-specific location keywords, but it
        // says "по всій території" so it should still be forwarded.
        let r = filter.process(
            "Alerts",
            "‼️увага! загроза застосування балістики середньої дальності (брсд) \
             по всій території україни. імовірний пуск ракети кедр/орєшнік (п/п рс-26). \
             перебувайте в безпечних місцях та не ігноруйте сигнали тривоги.",
        );
        assert!(r.is_some());
        let text = r.unwrap();
        assert!(text.contains("Балістика"));
        assert!(text.contains("ВСЯ УКРАЇНА"));
    }

    #[test]
    fn nationwide_shows_correct_tag() {
        let mut filter = kyiv_filter();
        let r = filter.process("Ch1", "загроза балістики по всій території україни");
        assert!(r.is_some());
        assert!(r.unwrap().contains("🟣 ВСЯ УКРАЇНА"));
    }

    #[test]
    fn nationwide_with_city_match_still_nationwide_tag() {
        // Even if Kyiv is mentioned, "по всій території" means nationwide.
        let mut filter = kyiv_filter();
        let r = filter.process(
            "Ch1",
            "баллистика по всей территории украины, в том числе на киев",
        );
        assert!(r.is_some());
        assert!(r.unwrap().contains("ВСЯ УКРАЇНА"));
    }

    // ── The exact sample message ──

    #[test]
    fn sample_oreshnik_brsd_nationwide() {
        let mut filter = kyiv_filter();
        let msg = "‼️Увага! Загроза застосування балістики середньої дальності (БРСД) \
                   по всій території України.\n\
                   \n\
                   Імовірний пуск ракети Кедр/Орєшнік (п/п РС-26).\n\
                   Перебувайте в безпечних місцях та не ігноруйте сигнали тривоги.";
        let r = filter.process("ПС ЗСУ", msg);
        assert!(r.is_some());
        let text = r.unwrap();
        // Must detect both Ballistic and Hypersonic
        assert!(text.contains("Балістика"));
        assert!(text.contains("Гіперзвук"));
        // Must show nationwide tag
        assert!(text.contains("ВСЯ УКРАЇНА"));
    }
}
