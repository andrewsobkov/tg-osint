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
    pub fn specificity(&self) -> u8 {
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
