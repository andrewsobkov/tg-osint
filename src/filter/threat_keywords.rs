use crate::filter::ThreatKind;

/// Keyword stems for each threat kind.  **Order matters** – more specific
/// variants must appear before generic ones so that the first match wins
/// during detection.
///
/// Each entry contains **both Ukrainian (UA) and Russian (RU)** stems.
pub const THREAT_KEYWORDS: &[(ThreatKind, &[&str])] = &[
    // ── All clear ──────────────────────────────────────────────────────
    (
        ThreatKind::AllClear,
        &[
            // UA
            "відбій", // відбій тривоги
            "загроза минула",
            "чисте небо",
            "дорозвідка",
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
    //
    // NOTE: "ціль"/"цель" (target) removed - too ambiguous without context.
    // Context window will handle these via threat history.
    (
        ThreatKind::Missile,
        &[
            "ракет",  // UA+RU: ракета, ракети, ракеты, ракетна …
            "запуск", // запуск ракет (more specific than "пуск")
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
pub const URGENCY_KEYWORDS: &[&str] = &[
    // UA
    "повторн",   // повторно, повторні, повторна, повторних…
    "додатково", // additionally
    "ще ціл",    // ще ціль / ще цілі – more targets
    "ще вихо",   // ще виходи / ще вихід – more launches
    "нові ціл",  // нові цілі
    "нова хвил", // нова хвиля (new wave)
    "увага!",    // УВАГА! – attention
    "терміново", // urgently
    "негайно",   // immediately (e.g. "негайно в укриття!")
    // RU
    "дополнительно",
    "ещё",
    "еще",
    "ще выход",    // more launches (RU variant)
    "новая волна", // new wave
    "внимание!",   // ВНИМАНИЕ!
    "срочно",      // urgently
    "немедленно",  // immediately
];

/// Returns `true` when the message contains an urgency keyword that should
/// bypass dedup.
pub fn is_urgent(lower: &str) -> bool {
    URGENCY_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

// ───────────────────── Nationwide alert detection ────────────────────────

/// Phrases that mean "the entire country" — these alerts are relevant to
/// everyone regardless of their configured oblast/city/district.
pub const NATIONWIDE_KEYWORDS: &[&str] = &[
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
