use anyhow::{Context, Result, anyhow};
use chrono::{FixedOffset, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Clone)]
pub(super) struct BotCfg {
    pub token: String,
    pub db_path: String,
}

#[derive(Clone)]
pub(super) struct ReplayCfg {
    pub input_path: String,
    pub speed: f64,
    pub fixed_step_ms: Option<u64>,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub broadcast: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DumpEvent {
    pub timestamp: i64,
    pub channel_id: i64,
    pub channel_title: String,
    pub text: String,
}

pub(super) fn must_env(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow!("Missing env var {key}"))
}

pub(super) fn parse_bool_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(default)
}

pub(super) fn load_bot_cfg() -> Result<BotCfg> {
    Ok(BotCfg {
        token: must_env("BOT_TOKEN")?,
        db_path: std::env::var("BOT_DB_PATH").unwrap_or_else(|_| "./bot_subscribers.sqlite".into()),
    })
}

pub(super) fn load_replay_cfg() -> Result<ReplayCfg> {
    let input_path = must_env("REPLAY_INPUT_PATH")?;
    let speed = std::env::var("REPLAY_SPEED")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(1.0);
    let fixed_step_ms = std::env::var("REPLAY_STEP_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0);
    let min_delay_ms = std::env::var("REPLAY_MIN_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let max_delay_ms = std::env::var("REPLAY_MAX_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10_000);

    Ok(ReplayCfg {
        input_path,
        speed,
        fixed_step_ms,
        min_delay_ms,
        max_delay_ms,
        broadcast: parse_bool_env("REPLAY_BROADCAST", false),
    })
}

pub(super) fn start_of_today_utc_from_offset(offset_minutes: i32) -> Result<i64> {
    let offset_secs = offset_minutes
        .checked_mul(60)
        .ok_or_else(|| anyhow!("DUMP_TZ_OFFSET_MINUTES is too large"))?;
    let offset =
        FixedOffset::east_opt(offset_secs).ok_or_else(|| anyhow!("Invalid timezone offset"))?;

    let now_local = Utc::now().with_timezone(&offset);
    let today = now_local.date_naive();
    let local_start = offset
        .from_local_datetime(&today.and_hms_opt(0, 0, 0).unwrap())
        .single()
        .ok_or_else(|| anyhow!("Failed to build local midnight timestamp"))?;
    Ok(local_start.with_timezone(&Utc).timestamp())
}

pub(super) fn load_dump_events(path: &str) -> Result<Vec<DumpEvent>> {
    let file = File::open(path).with_context(|| format!("failed to open replay file {path}"))?;
    let reader = BufReader::new(file);

    let mut events = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("failed to read line {}", idx + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let event: DumpEvent = serde_json::from_str(&line)
            .with_context(|| format!("invalid JSON at line {}", idx + 1))?;
        events.push(event);
    }

    events.sort_by_key(|e| (e.timestamp, e.channel_id));
    Ok(events)
}
