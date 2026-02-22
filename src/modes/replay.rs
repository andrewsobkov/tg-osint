use crate::{bot, filter, llm};
use anyhow::{Result, anyhow};
use reqwest::Client as HttpClient;
use std::time::Duration;
use tracing::{info, warn};

use super::shared::{load_bot_cfg, load_dump_events, load_replay_cfg};

pub(super) async fn run() -> Result<()> {
    let replay = load_replay_cfg()?;
    let events = load_dump_events(&replay.input_path)?;
    if events.is_empty() {
        return Err(anyhow!("Replay input is empty: {}", replay.input_path));
    }

    let llm_filter = llm::LlmFilter::from_env();
    let mut alert_filter = filter::AlertFilter::from_env();
    info!(
        "Replay started: {} events from {}",
        events.len(),
        replay.input_path
    );
    info!("Filter config: {alert_filter}");
    info!("LLM filter: {llm_filter}");

    let mut bot_ctx = None;
    if replay.broadcast {
        let bot_cfg = load_bot_cfg()?;
        let db = bot::open_db(&bot_cfg.db_path)?;
        bot_ctx = Some((HttpClient::new(), bot_cfg.token, db));
        info!("Replay broadcast enabled; alerts will be sent to bot subscribers");
    }

    let mut forwarded = 0usize;
    let mut suppressed = 0usize;

    for (idx, event) in events.iter().enumerate() {
        if idx > 0 {
            let prev = &events[idx - 1];
            let delay_ms = if let Some(step_ms) = replay.fixed_step_ms {
                step_ms
            } else {
                let delta_s = (event.timestamp - prev.timestamp).max(0) as f64;
                let scaled = (delta_s * 1000.0 / replay.speed).round() as u64;
                scaled.clamp(replay.min_delay_ms, replay.max_delay_ms)
            };
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }

        let result = alert_filter
            .process_with_llm(
                event.channel_id,
                &event.channel_title,
                &event.text,
                &llm_filter,
            )
            .await;

        if let Some(formatted) = result {
            forwarded += 1;
            if let Some((http, token, db)) = &bot_ctx {
                if let Err(e) = bot::broadcast(http, token, db, &formatted).await {
                    warn!("Failed to broadcast replayed alert: {e}");
                }
            } else {
                println!("\n[REPLAY ALERT {}]\n{}\n", idx + 1, formatted);
            }
        } else {
            suppressed += 1;
        }
    }

    info!(
        "Replay complete: total={}, forwarded={}, suppressed={}",
        events.len(),
        forwarded,
        suppressed
    );

    Ok(())
}
