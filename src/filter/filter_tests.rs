// ─────────────────────────────── Tests ───────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    //use crate::filter::{AlertFilter, LocationConfig};

    use crate::filter::{detect_threats, *};

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
    fn detects_target_with_context() {
        // "ціль"/"цель" (target) now requires context to infer threat type.
        // Without context, it won't trigger from keywords alone.
        let threats = detect_threats("ще ціль на київ");
        assert!(!threats.contains(&ThreatKind::Missile));

        // But with "ракет" keyword, it should still work
        let threats2 = detect_threats("2 ракети на київ");
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

    #[test]
    fn zircon_kr_phrase_is_hypersonic_only() {
        let threats = detect_threats("КР Циркон на Київ");
        assert!(threats.contains(&ThreatKind::Hypersonic));
        assert!(
            !threats.contains(&ThreatKind::CruiseMissile),
            "Zircon phrase should not be dual-labeled as CruiseMissile: {threats:?}"
        );
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

    #[test]
    fn detects_aircraft_borts_sa_combo() {
        // Real dump pattern: "бортів СА ... в повітря".
        let threats = detect_threats("близько 5 бортів СА піднято в повітря");
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

    #[test]
    fn detects_cruise_missile_abbrev_kr_combo() {
        // Real dump pattern: "2х КР курсом на ...".
        let threats = detect_threats("2х КР курсом на Гадяч");
        assert!(threats.contains(&ThreatKind::CruiseMissile));
        assert!(!threats.contains(&ThreatKind::Missile));
    }

    #[test]
    fn detects_cruise_missile_abbrev_kr_with_location() {
        // Real dump pattern: "КР на ... курсом на ...".
        let threats = detect_threats("КР на Сумщині курсом на Липову Долину");
        assert!(threats.contains(&ThreatKind::CruiseMissile));
    }

    #[test]
    fn detects_fast_target_combo_ua() {
        // Real dump pattern: "Швидкісна ціль ... курсом ...".
        let threats = detect_threats("Швидкісна ціль на Чернігівщині, курсом на Київ.");
        assert!(threats.contains(&ThreatKind::Missile));
    }

    #[test]
    fn detects_fast_target_combo_ru() {
        let threats = detect_threats("Скоростная цель курсом на город");
        assert!(threats.contains(&ThreatKind::Missile));
    }

    #[test]
    fn no_false_cruise_on_kr_inside_word() {
        // "кр" inside a larger token must not be treated as cruise abbreviation.
        let threats = detect_threats("ситуація в кролевці спокійна");
        assert!(
            !threats.contains(&ThreatKind::CruiseMissile),
            "embedded 'кр' should not trigger CruiseMissile: {threats:?}"
        );
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
        // "ціль"/"цель" patterns are handled by context inference (not raw
        // keyword detection). Verify they are caught via process_with_id.
        // Use a fresh filter per case so dedup does not mask trigger matching.
        let run = |msg: &str| {
            let mut filter = kyiv_filter();
            filter.forward_all_threats = true; // bypass location for these checks
            filter.process_with_id(1, "Ch", msg)
        };

        let r1 = run("ціль на київ!");
        assert!(r1.is_some(), "\"ціль на\" must match via context inference");

        let r2 = run("2 цілі на захід");
        assert!(r2.is_some(), "\"цілі на\" must match via context inference");

        let r3 = run("цель на киев");
        assert!(r3.is_some(), "\"цель на\" must match via context inference");

        let r4 = run("3 цели на днепр");
        assert!(r4.is_some(), "\"цели \" must match via context inference");

        // End-of-string / end-of-line
        let r5 = run("нова ціль");
        assert!(
            r5.is_some(),
            "\"ціль\" at end must match via context inference"
        );

        let r6 = run("ще одна ціль\nна захід");
        assert!(r6.is_some(), "\"ціль\\n\" must match via context inference");
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
    fn process_skips_informational_statistics_post() {
        // Real-world recap format from official channels: many threat words,
        // but mostly retrospective statistics and battle-damage summary.
        let mut filter = kyiv_filter();
        let msg = "⚡️ ЗБИТО/ПОДАВЛЕНО 33 РАКЕТИ ТА 274 ВОРОЖИХ БПЛА\n\
                   У ніч на 22 лютого противник завдав комбінованого удару.\n\
                   Усього зафіксовано 345 засобів повітряного нападу:\n\
                   - 4 протикорабельні ракети \"Циркон\";\n\
                   - 22 балістичні ракети Іскандер-М/С-400;\n\
                   - 18 крилатих ракет Х-101;\n\
                   - 297 ударних БпЛА.\n\
                   За попередніми даними, станом на 10:00, збито/подавлено 307 цілей.\n\
                   Зафіксовано влучання на 14 локаціях.\n\
                   Інформація щодо кількох ворожих ракет уточнюється.\n\
                   ✊Тримаймо небо!\n\
                   🇺🇦 Разом – до перемоги!";
        let r = filter.process("ПС ЗСУ", msg);
        assert!(
            r.is_none(),
            "Large retrospective statistics post should be suppressed"
        );
    }

    #[test]
    fn informational_filter_keeps_live_movement_alert() {
        let mut filter = kyiv_filter();
        let r = filter.process("ПС ЗСУ", "Швидкісна ціль на Чернігівщині, курсом на Київ.");
        assert!(
            r.is_some(),
            "Live trajectory alert must NOT be suppressed as informational"
        );
    }

    #[test]
    fn process_negative_status_updates_once_per_wave() {
        let mut filter = kyiv_filter();
        filter.forward_all_threats = true;
        filter.negative_status_cooldown = Duration::from_secs(0);

        // Seed active context first.
        let _ = filter.process("monitor", "КР Циркон на Київ");

        let r1 = filter.process("monitor", "Більше не спостерігається, пролунав вибух.");
        assert!(
            r1.is_some(),
            "first negative-status phrasing in active wave should be forwarded once"
        );
        assert!(r1.unwrap().contains("ℹ️ Статус"));

        let r2 = filter.process("monitor", "Не фіксуються.");
        assert!(
            r2.is_none(),
            "subsequent negative-status updates should be suppressed in same wave"
        );

        // A visible threat again should unlock one more status update.
        let _ = filter.process("monitor", "Ще ракети з Криму!");
        let r3 = filter.process("monitor", "Все");
        assert!(
            r3.is_some(),
            "after threat becomes visible again, status update should pass once"
        );
    }

    #[test]
    fn negative_status_with_possible_repeat_launch_is_status() {
        let mut filter = kyiv_filter();
        filter.forward_all_threats = true;
        filter.negative_status_cooldown = Duration::from_secs(0);

        let _ = filter.process("monitor", "Балістика на Київ");
        let r = filter.process(
            "monitor",
            "По балістиці поки чисто. Можливі повторні пуски.",
        );
        assert!(
            r.is_some(),
            "status update should be forwarded once per wave"
        );
        let text = r.unwrap();
        assert!(text.contains("ℹ️ Статус"));
        assert!(
            !text.contains("‼️🚀 Балістика"),
            "status phrasing must not be forwarded as active ballistic threat"
        );
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

    #[test]
    fn proximity_city_phrase_does_not_capture_kyivshchyna() {
        let loc = LocationConfig {
            oblast: vec!["київщин".into()],
            city: vec!["на київ".into()],
            district: vec![],
        };
        let p = loc.check("2 циркони, курсом на київщину");
        assert_eq!(
            p,
            Proximity::Oblast,
            "city phrase must not match inside 'київщину'"
        );
    }

    #[test]
    fn resolve_location_city_and_oblast_phrase_prefers_oblast() {
        let filter = kyiv_filter();
        let (p, nationwide) = filter.resolve_location("ракети на київ та область", "any");
        assert!(!nationwide);
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
    fn dedup_allows_nationwide_after_local() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "баллистика на киев!");
        assert!(r1.is_some());

        // Must still forward because nationwide scope changed (larger impact),
        // even though proximity is not an upgrade.
        let r2 = filter.process("Ch2", "баллистика по всей территории украины");
        assert!(r2.is_some(), "Nationwide alert should bypass local dedup");
        assert!(r2.unwrap().contains("ВСЯ УКРАЇНА"));
    }

    #[test]
    fn dedup_allows_new_secondary_threat_same_primary() {
        let mut filter = kyiv_filter();
        let r1 = filter.process("Ch1", "баллистика на киев");
        assert!(r1.is_some());

        // Primary remains Ballistic, but Shahed is new info and should pass.
        let r2 = filter.process("Ch2", "баллистика та шахеди на київ");
        assert!(
            r2.is_some(),
            "New secondary threat should not be suppressed by primary-kind dedup"
        );
        let text = r2.unwrap();
        assert!(text.contains("Балістика"));
        assert!(text.contains("Шахед"));
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
    fn same_channel_urgent_respects_cooldown() {
        let mut filter = kyiv_filter();
        filter.urgent_same_channel_cooldown = Duration::from_millis(60);

        let r1 = filter.process("Ch1", "баллистика на киев!");
        assert!(r1.is_some());

        let r2 = filter.process("Ch1", "повторно баллистика на киев!");
        assert!(r2.is_some(), "first urgent re-alert should pass");

        let r3 = filter.process("Ch1", "повторно баллистика на киев!");
        assert!(
            r3.is_none(),
            "urgent re-alert inside cooldown should be throttled"
        );

        std::thread::sleep(Duration::from_millis(70));
        let r4 = filter.process("Ch1", "повторно баллистика на киев!");
        assert!(
            r4.is_some(),
            "urgent re-alert after cooldown should pass again"
        );
    }

    #[test]
    fn dump_fragment_ballistic_burst_expected_forwards() {
        // Condensed replay of the 2026-02-22 burst around lines 140..224.
        // Expected with current logic:
        // 1) first city-level Ballistic alert -> forward
        // 2) "4 ракети на Київ" is refined to Ballistic from burst context -> deduped
        // 3) first urgent same-threat re-alert ("повторний вихід") -> forward
        // all other duplicates in the short window -> suppressed
        let mut filter = kyiv_filter();

        let ch_monitor: i64 = 1641260594;
        let ch_kyiv_nebo: i64 = 2146225839;
        let ch_radar: i64 = 1779278127;
        let ch_monitoring: i64 = 1550485924;
        let ch_kyiv_ad: i64 = 2486466109;

        let inputs = [
            // No Kyiv location yet -> seeds context, not forwarded.
            (
                ch_monitor,
                "monitor",
                "🟣 Загроза балістики з Північного Сходу. Брянськ.",
            ),
            // First city Ballistic.
            (ch_kyiv_nebo, "Київське небо 🌌", "Балістика на Київ"),
            // Generic wording, but should be treated as Ballistic in this context.
            (ch_radar, "Чому тривога | Радар", "4 ракети на Київ"),
            // Duplicate Ballistic with city -> suppressed.
            (
                ch_monitoring,
                "monitoring",
                "Виходи балістики з Брянської області. Київ/область — уважно.",
            ),
            // Phrase with no explicit threat keyword; inferred from context and deduped.
            (ch_kyiv_ad, "Kyiv AirDefense 🌇", "Швидкісні на Київ!"),
            // Urgent re-alert from the same monitor channel -> forwarded.
            (ch_monitor, "monitor", "☄ Повторний вихід у напрямку Київ"),
            // Another duplicate Ballistic -> suppressed.
            (ch_monitoring, "monitoring", "Балістика на Київ."),
        ];

        let mut forwarded = Vec::new();
        for (ch_id, title, text) in inputs {
            if let Some(alert) = filter.process_with_id(ch_id, title, text) {
                forwarded.push(alert);
            }
        }

        assert_eq!(
            forwarded.len(),
            2,
            "Expected exactly 2 forwarded alerts in this burst"
        );
        assert!(
            forwarded.iter().any(|a| a.contains("Балістика")),
            "Should forward a Ballistic city alert"
        );
        assert!(
            forwarded.iter().any(|a| a.contains("ПОВТОРНО")),
            "Should forward one urgent re-alert"
        );
    }

    #[test]
    fn global_context_refines_generic_rocket_to_ballistic() {
        let mut filter = kyiv_filter();
        let ch1: i64 = 900001;
        let ch2: i64 = 900002;

        // Seed global context with Ballistic, but without user location match,
        // so it doesn't produce an outward alert.
        let seed = filter.process_with_id(ch1, "Seed", "загроза балістики з брянська");
        assert!(seed.is_none());

        // Generic "ракети" should be refined to Ballistic from recent context.
        let r = filter.process_with_id(ch2, "Radar", "4 ракети на київ");
        assert!(r.is_some());
        let text = r.unwrap();
        assert!(
            text.contains("Балістика"),
            "Should refine to Ballistic: {text}"
        );
        assert!(
            !text.contains("Ракета"),
            "Should avoid generic Missile label in this context: {text}"
        );
    }

    #[test]
    fn global_context_does_not_refine_generic_missile_to_shahed() {
        let mut filter = kyiv_filter();
        let ch_shahed: i64 = 910001;
        let ch_generic: i64 = 910002;

        let _ = filter.process_with_id(ch_shahed, "Seed", "шахеди біля узина");
        let r = filter.process_with_id(ch_generic, "Radar", "4 ракети на київ!");
        assert!(r.is_some());
        let text = r.unwrap();
        assert!(
            !text.contains("Шахед"),
            "generic missile/trajectory message must not be promoted to Shahed: {text}"
        );
    }

    #[test]
    fn live_movement_other_does_not_refine_when_explicit_nonlocal() {
        let mut filter = kyiv_filter();
        let ch_hyp: i64 = 920001;
        let ch_other: i64 = 920002;

        // Seed global threat context without creating a forwarded/deduped alert.
        let _ = filter.process_with_id(ch_hyp, "Seed", "циркон");
        // Seed location context for the Aeris channel (mirrors replay behavior).
        let _ = filter.process_with_id(ch_other, "Aeris Rimor", "на київ");
        filter.forward_all_threats = true;
        let r = filter.process_with_id(
            ch_other,
            "Aeris Rimor",
            "Залітає на Кіровоградщину.\n\nУкраїнка навколо укриття.",
        );
        assert!(r.is_some());
        let text = r.unwrap();
        assert!(
            text.contains("⚠️ Загроза"),
            "explicit non-local message should stay generic and not inherit local missile context: {text}"
        );
        assert!(
            !text.contains("Гіперзвук"),
            "non-local live message should not be promoted to local hypersonic alert: {text}"
        );
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

    // ── Context window tests ──

    #[test]
    fn context_infers_ballistic_from_recent_message() {
        let mut filter = kyiv_filter();
        let channel_id = 123456;

        // First message: mentions ballistic — seeds context window.
        // (May not be forwarded if it doesn't match the user's location.)
        let _r1 = filter.process_with_id(channel_id, "TestChannel", "балістична загроза з півдня");

        // Second message: just "ціль" (target) - should infer Ballistic from context
        let r2 = filter.process_with_id(channel_id, "TestChannel", "ціль на київ");
        assert!(r2.is_some());
        let text = r2.unwrap();
        assert!(
            text.contains("Балістика"),
            "Should infer Ballistic from context"
        );
    }

    #[test]
    fn context_fallback_does_not_relabel_explicit_nonlocal_message() {
        let mut filter = kyiv_filter();
        let channel_id = 700001;

        let _ = filter.process_with_id(channel_id, "Kyiv AirDefense 🌇", "Балістика на Київ");

        let r = filter.process_with_id(
            channel_id,
            "Kyiv AirDefense 🌇",
            "🛵 Група БпЛА на Харків з півдня.",
        );
        assert!(
            r.is_none(),
            "explicit non-local (Kharkiv) text must not inherit local Kyiv proximity from context/title"
        );
    }

    #[test]
    fn context_district_fallback_is_capped_to_city() {
        let mut filter = kyiv_filter();
        let channel_id = 700002;
        filter.forward_all_threats = true;

        let _ = filter.process_with_id(
            channel_id,
            "Kyiv AirDefense 🌇",
            "‼️ Загроза балістики у Голосіївському районі",
        );
        let r = filter.process_with_id(channel_id, "Kyiv AirDefense 🌇", "ПОВТОРНО РАКЕТИ!");
        assert!(r.is_some());
        let text = r.unwrap();
        assert!(
            !text.contains("🔴 РАЙОН"),
            "fallback proximity should not keep district stickiness: {text}"
        );
    }

    #[test]
    fn context_infers_cruise_missile_from_recent_message() {
        let mut filter = kyiv_filter();
        let channel_id = 789012;

        // First message: cruise missile (forwarded at City proximity)
        let r1 = filter.process_with_id(channel_id, "TestChannel", "крилата ракета калібр на київ");
        assert!(r1.is_some());

        // Second message: just "2 цілі" — should infer CruiseMissile.
        // Use district-level location so proximity upgrades past r1's City
        // and dedup lets it through.
        let r2 =
            filter.process_with_id(channel_id, "TestChannel", "2 цілі на шевченківський район");
        assert!(r2.is_some());
        let text = r2.unwrap();
        assert!(
            text.contains("Крилата ракета"),
            "Should infer CruiseMissile from context"
        );
    }

    #[test]
    fn context_infers_shahed_from_dron_keyword() {
        let mut filter = kyiv_filter();
        let channel_id = 345678;

        // First message: mentions drones — seeds context window.
        // (May not be forwarded if it doesn't match the user's location.)
        let _r1 = filter.process_with_id(channel_id, "TestChannel", "шахеди в повітрі");

        // Second message: "цель" should infer Shahed
        let r2 = filter.process_with_id(channel_id, "TestChannel", "ще цель на київ");
        assert!(r2.is_some());
        let text = r2.unwrap();
        assert!(
            text.contains("Шахед") || text.contains("дрон"),
            "Should infer Shahed from context"
        );
    }

    #[test]
    fn context_separate_per_channel() {
        let mut filter = kyiv_filter();
        let channel1 = 111111;
        let channel2 = 222222;

        // Channel 1: ballistic
        filter.process_with_id(channel1, "Channel1", "балістична ракета");

        // Channel 2: cruise missile
        filter.process_with_id(channel2, "Channel2", "крилата ракета");

        // Channel 1: "ціль" should infer Ballistic
        let r1 = filter.process_with_id(channel1, "Channel1", "ціль на київ");
        if let Some(text) = r1 {
            assert!(
                text.contains("Балістика"),
                "Channel 1 should infer Ballistic"
            );
        }

        // Channel 2: "ціль" should infer CruiseMissile
        let r2 = filter.process_with_id(channel2, "Channel2", "ціль на київ");
        if let Some(text) = r2 {
            assert!(
                text.contains("Крилата ракета"),
                "Channel 2 should infer CruiseMissile"
            );
        }
    }

    #[test]
    fn context_defaults_to_missile_without_history() {
        let mut filter = kyiv_filter();
        let channel_id = 999999;

        // No prior messages, just "ціль" - should default to generic Missile
        let r = filter.process_with_id(channel_id, "TestChannel", "ціль на київ");
        assert!(r.is_some());
        let text = r.unwrap();
        // Should have some threat indicator, defaulting to Missile
        assert!(text.contains("Ракета"), "Should default to generic Missile");
    }

    #[test]
    fn context_tsel_without_trigger_does_not_alert() {
        let mut filter = kyiv_filter();

        // "цель" alone in analytical text should not trigger without context
        let threats = detect_threats("достичь цели операции");
        assert!(threats.is_empty(), "Analytical 'цель' should not trigger");
    }

    // ── Location-aware context window tests ──

    #[test]
    fn context_location_only_infers_threat() {
        // A message with just a location (no threat keyword) should infer
        // the threat type from recent channel context.
        let mut filter = kyiv_filter();
        let ch = 400001;

        // Seed: threat without location → not forwarded, but seeds context
        let r1 = filter.process_with_id(ch, "Ch", "вихід балістики");
        assert!(r1.is_none(), "No location → should NOT forward");

        // Follow-up: just a location → infer Ballistic from context
        let r2 = filter.process_with_id(ch, "Ch", "на київ");
        assert!(
            r2.is_some(),
            "Should infer Ballistic from context + Київ location"
        );
        let text = r2.unwrap();
        assert!(
            text.contains("Балістика"),
            "Should contain Ballistic threat: {text}"
        );
    }

    #[test]
    fn context_threat_infers_location() {
        // When a channel already has a location in context, a new threat
        // without location should infer the location.
        let mut filter = kyiv_filter();
        let ch = 400002;

        // Seed: Ballistic with location → forwarded
        let r1 = filter.process_with_id(ch, "Ch", "балістика на київ");
        assert!(r1.is_some());

        // New threat type, no location → should infer City from context
        // (Different threat kind bypasses dedup)
        let r2 = filter.process_with_id(ch, "Ch", "крилата ракета");
        assert!(
            r2.is_some(),
            "Should infer location from context and forward"
        );
        let text = r2.unwrap();
        assert!(
            text.contains("Крилата ракета"),
            "Should contain CruiseMissile: {text}"
        );
    }

    #[test]
    fn context_urgent_infers_both_threat_and_location() {
        // "повторно" alone should infer both threat and location from context.
        let mut filter = kyiv_filter();
        let ch = 400003;

        // Seed with threat + location
        let r1 = filter.process_with_id(ch, "Ch", "балістика на київ");
        assert!(r1.is_some());

        // "повторно" with nothing else → infer Ballistic + City from context
        let r2 = filter.process_with_id(ch, "Ch", "повторно");
        assert!(
            r2.is_some(),
            "Should infer both threat+location from context"
        );
        let text = r2.unwrap();
        assert!(text.contains("ПОВТОРНО"), "Should have urgency tag: {text}");
        assert!(text.contains("Балістика"), "Should infer Ballistic: {text}");
    }

    #[test]
    fn context_launch_trigger_infers_threat() {
        // "виходи" (launches) should trigger inference like "ціль" does.
        let mut filter = kyiv_filter();
        filter.forward_all_threats = true; // bypass location for this check
        let ch = 400004;

        // Seed: ballistic
        filter.process_with_id(ch, "Ch", "балістична загроза");

        // "ще виходи" should infer Ballistic
        let r = filter.process_with_id(ch, "Ch", "ще виходи на київ");
        assert!(r.is_some(), "Launch trigger should infer from context");
        let text = r.unwrap();
        assert!(text.contains("Балістика"), "Should infer Ballistic: {text}");
    }

    #[test]
    fn context_multichannel_scenario() {
        // Full scenario from the user's description:
        //   ch1: "вихід балістики"     → no location → not forwarded
        //   ch2: "балістика брянськ"   → no location → not forwarded
        //   ch1: "на київ"             → infer Ballistic → FORWARDED
        //   ch2: "вектором на Київ"    → infer Ballistic → DEDUPED
        //   ch1: "2 цілі на київ"      → infer Ballistic → DEDUPED
        //   ch2: "повторно"            → urgent, infer both → FORWARDED
        //   ch1: "повторні виходи"     → urgent echo → DEDUPED
        let mut filter = kyiv_filter();
        let ch1: i64 = 500001;
        let ch2: i64 = 500002;

        // 1. ch1: threat, no location → not forwarded
        let r1 = filter.process_with_id(ch1, "Ch1", "вихід балістики");
        assert!(r1.is_none(), "Step 1: no location → skip");

        // 2. ch2: threat, launch location (брянськ) not in user config → not forwarded
        let r2 = filter.process_with_id(ch2, "Ch2", "балістика брянськ");
        assert!(
            r2.is_none(),
            "Step 2: брянськ is launch location, not user's → skip"
        );

        // 3. ch1: just location → infer Ballistic from ch1 context → FORWARD
        let r3 = filter.process_with_id(ch1, "Ch1", "на київ");
        assert!(r3.is_some(), "Step 3: infer Ballistic + Київ → forward");
        let text3 = r3.unwrap();
        assert!(
            text3.contains("Балістика"),
            "Step 3: should contain Ballistic: {text3}"
        );

        // 4. ch2: location → infer Ballistic from ch2 context → DEDUP
        let r4 = filter.process_with_id(ch2, "Ch2", "вектором на Київ");
        assert!(
            r4.is_none(),
            "Step 4: same threat+location from different channel → dedup"
        );

        // 5. ch1: "цілі" trigger + location → DEDUP
        let r5 = filter.process_with_id(ch1, "Ch1", "2 цілі на київ");
        assert!(r5.is_none(), "Step 5: same threat+location → dedup");

        // 6. ch2: urgent, no keyword, no location → infer both from context → FORWARD
        let r6 = filter.process_with_id(ch2, "Ch2", "повторно");
        assert!(
            r6.is_some(),
            "Step 6: urgent infers Ballistic+Київ → forward"
        );
        let text6 = r6.unwrap();
        assert!(text6.contains("ПОВТОРНО"), "Step 6: urgency tag: {text6}");
        assert!(
            text6.contains("Балістика"),
            "Step 6: should contain Ballistic: {text6}"
        );

        // 7. ch1: urgent echo → DEDUP
        let r7 = filter.process_with_id(ch1, "Ch1", "повторні виходи");
        assert!(
            r7.is_none(),
            "Step 7: urgent echo from different channel → dedup"
        );

        // 8. ch2: same-channel re-alert → FORWARD (genuine new wave from same source)
        let r8 = filter.process_with_id(ch2, "Ch2", "ще виходи");
        assert!(r8.is_some(), "Step 8: same-channel re-alert → forward");
        let text8 = r8.unwrap();
        assert!(
            text8.contains("Балістика"),
            "Step 8: should contain Ballistic: {text8}"
        );
    }

    #[test]
    fn context_all_clear_resets_context() {
        // After AllClear, stale threats should not be inferred.
        let mut filter = kyiv_filter();
        let ch = 400005;

        // Seed: ballistic
        filter.process_with_id(ch, "Ch", "балістика на київ");

        // AllClear → clears both dedup cache and context
        let r_clear = filter.process_with_id(ch, "Ch", "відбій тривоги");
        assert!(r_clear.is_some());
        assert!(r_clear.unwrap().contains("Відбій"));

        // Now "на київ" alone should NOT forward (no threat in context)
        let r_after = filter.process_with_id(ch, "Ch", "на київ");
        assert!(
            r_after.is_none(),
            "After AllClear, should not infer stale threats"
        );
    }

    #[test]
    fn context_urgency_povtorni() {
        // "повторні" (adjective plural) should also trigger urgency
        // via the "повторн" stem.
        assert!(is_urgent("повторні виходи"));
    }

    #[test]
    fn context_urgency_shche_vykho() {
        // "ще виходи" (more launches) should trigger urgency.
        assert!(is_urgent("ще виходи на київ"));
    }
}
