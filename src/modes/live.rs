use crate::{bot, filter, llm, telegram};
use anyhow::{Context, Result};
use grammers_client::Update;
use reqwest::Client as HttpClient;
use std::collections::HashSet;
use tracing::{info, warn};

use super::shared::load_bot_cfg;

pub(super) async fn run() -> Result<()> {
    let tg = telegram::load_tg_cfg()?;
    let bot_cfg = load_bot_cfg()?;

    let bot_db = bot::open_db(&bot_cfg.db_path)?;
    {
        let http = HttpClient::new();
        let token = bot_cfg.token.clone();
        let db = bot_db.clone();
        tokio::spawn(async move {
            bot::run_bot_polling(http, token, db).await;
        });
    }

    let (client, pool) = telegram::connect(&tg)?;

    let runner = pool.runner;
    tokio::spawn(async move {
        runner.run().await;
    });

    let updates_rx = pool.updates;

    telegram::ensure_user_login(&client, &tg).await?;

    let mut allowed_peer_ids: HashSet<i64> = HashSet::new();
    for uname in &tg.channels {
        let peer = client
            .resolve_username(uname)
            .await
            .with_context(|| format!("resolve_username failed for @{uname}"))?;
        if let Some(peer) = peer {
            allowed_peer_ids.insert(peer.id().bare_id());
            info!("Watching @{uname} (peer_id={})", peer.id().bare_id());
        }
    }

    let mut stream = client.stream_updates(
        updates_rx,
        grammers_client::UpdatesConfiguration {
            catch_up: true,
            update_queue_limit: Some(2048),
        },
    );

    let http = HttpClient::new();
    let mut alert_filter = filter::AlertFilter::from_env();
    info!("Filter config: {alert_filter}");

    let llm_filter = llm::LlmFilter::from_env();
    info!("LLM filter: {llm_filter}");

    info!("Running in live mode. Waiting for new messages...");
    loop {
        let Ok(update) = stream.next().await else {
            warn!("Update stream ended.");
            break;
        };

        if let Update::NewMessage(msg) = update {
            let Ok(peer) = msg.peer() else {
                continue;
            };
            if !allowed_peer_ids.contains(&peer.id().bare_id()) {
                continue;
            }
            let text = msg.text().trim();
            if text.is_empty() {
                continue;
            }
            let title = peer.name().unwrap_or("<unknown>");
            let channel_id = peer.id().bare_id();

            let result = alert_filter
                .process_with_llm(channel_id, title, text, &llm_filter)
                .await;

            if let Some(formatted) = result {
                info!("Alert forwarded from @{title}");
                if let Err(e) = bot::broadcast(&http, &bot_cfg.token, &bot_db, &formatted).await {
                    warn!("Failed to broadcast alert: {e}");
                }
            }
        }
    }

    Ok(())
}
