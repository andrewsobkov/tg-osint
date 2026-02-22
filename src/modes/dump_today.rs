use crate::telegram;
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use tracing::{info, warn};

use super::shared::{DumpEvent, start_of_today_utc_from_offset};

pub(super) async fn run() -> Result<()> {
    let tg = telegram::load_tg_cfg()?;
    let output_path =
        std::env::var("DUMP_OUTPUT_PATH").unwrap_or_else(|_| "./dump_today.jsonl".into());
    let offset_minutes = std::env::var("DUMP_TZ_OFFSET_MINUTES")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let now_ts = Utc::now().timestamp();
    let since_ts = start_of_today_utc_from_offset(offset_minutes)?;

    let (client, pool) = telegram::connect(&tg)?;

    let runner = pool.runner;
    tokio::spawn(async move {
        runner.run().await;
    });

    telegram::ensure_user_login(&client, &tg).await?;

    info!(
        "Dumping messages from {} channels since UTC timestamp={} (tz offset {} min)",
        tg.channels.len(),
        since_ts,
        offset_minutes
    );

    let mut events: Vec<DumpEvent> = Vec::new();

    for uname in &tg.channels {
        let peer = client
            .resolve_username(uname)
            .await
            .with_context(|| format!("resolve_username failed for @{uname}"))?;
        let Some(peer) = peer else {
            warn!("Username @{uname} was not resolved; skipping");
            continue;
        };

        let channel_id = peer.id().bare_id();
        let title = peer.name().unwrap_or("<unknown>").to_string();
        info!("Scanning @{uname} ({title}, id={channel_id})");

        let mut iter = client.iter_messages(peer).max_date(now_ts as i32);
        while let Some(msg) = iter.next().await.context("iter_messages failed")? {
            let ts = msg.date().timestamp();
            if ts < since_ts {
                break;
            }

            let text = msg.text().trim();
            if text.is_empty() {
                continue;
            }

            events.push(DumpEvent {
                timestamp: ts,
                channel_id,
                channel_title: title.clone(),
                text: text.to_string(),
            });
        }
    }

    events.sort_by_key(|e| (e.timestamp, e.channel_id));

    if let Some(parent) = Path::new(&output_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create parent directory for output dump file {}",
                    output_path
                )
            })?;
        }
    }

    let file = File::create(&output_path)
        .with_context(|| format!("failed to create output dump file {output_path}"))?;
    let mut writer = BufWriter::new(file);

    for event in &events {
        let line = serde_json::to_string(event)?;
        writer.write_all(line.as_bytes())?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;

    info!(
        "Dump complete: {} events written to {}",
        events.len(),
        output_path
    );

    Ok(())
}
