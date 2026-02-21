mod bot;
mod filter;

use anyhow::{Context, Result, anyhow};
use dotenvy::dotenv;
use grammers_client::{Client, SignInError, Update};
use grammers_mtsender::SenderPool;
use grammers_session::storages::SqliteSession;
use reqwest::Client as HttpClient;
use std::{collections::HashSet, io::Write, sync::Arc};
use tokio::io::{self, AsyncBufReadExt};
use tracing::{info, warn};

#[derive(Clone)]
struct Cfg {
    api_id: i32,
    api_hash: String,
    phone: String,
    two_fa_password: Option<String>,
    session_path: String,
    channels: Vec<String>,
    bot_token: String,
    /// Path to the SQLite file that stores subscriber chat IDs.
    bot_db_path: String,
}

fn must_env(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow!("Missing env var {key}"))
}

fn parse_channels(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().trim_start_matches('@'))
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect()
}

async fn read_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let mut stdin = io::BufReader::new(io::stdin());
    stdin.read_line(&mut line).await?;
    Ok(line.trim().to_string())
}

async fn ensure_user_login(client: &Client, cfg: &Cfg) -> Result<()> {
    if client.is_authorized().await? {
        return Ok(());
    }

    info!("Not authorized. Requesting login code...");
    let token = client
        .request_login_code(&cfg.phone, &cfg.api_hash)
        .await
        .context("request_login_code failed")?;

    let code = read_line("Enter the login code you received: ").await?;

    match client.sign_in(&token, &code).await {
        Ok(user) => {
            info!(
                "Signed in as {:?}",
                user.first_name().unwrap_or("<unknown>")
            );
            Ok(())
        }
        Err(SignInError::PasswordRequired(password_token)) => {
            let pw = if let Some(pw) = &cfg.two_fa_password {
                pw.clone()
            } else {
                let hint = password_token.hint().unwrap_or("");
                read_line(&format!(
                    "2FA password required (hint: {hint}). Enter password: "
                ))
                .await?
            };

            client
                .check_password(password_token, pw.as_bytes())
                .await
                .context("check_password failed")?;

            info!("Signed in with 2FA.");
            Ok(())
        }
        Err(e) => Err(anyhow!("sign_in failed: {e}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt().with_target(false).init();

    let cfg = Cfg {
        api_id: must_env("TG_API_ID")?
            .parse()
            .context("TG_API_ID must be i32")?,
        api_hash: must_env("TG_API_HASH")?,
        phone: must_env("TG_PHONE")?,
        two_fa_password: std::env::var("TG_2FA_PASSWORD").ok(),
        session_path: std::env::var("TG_SESSION_PATH")
            .unwrap_or_else(|_| "./telegram.session.sqlite".into()),
        channels: parse_channels(&must_env("TG_CHANNELS")?),
        bot_token: must_env("BOT_TOKEN")?,
        bot_db_path: std::env::var("BOT_DB_PATH")
            .unwrap_or_else(|_| "./bot_subscribers.sqlite".into()),
    };

    if cfg.channels.is_empty() {
        return Err(anyhow!("TG_CHANNELS is empty"));
    }

    // Open subscriber database and start bot long-poll in the background.
    let bot_db = bot::open_db(&cfg.bot_db_path)?;
    {
        let http = HttpClient::new();
        let bot_token = cfg.bot_token.clone();
        let db = bot_db.clone();
        tokio::spawn(async move {
            bot::run_bot_polling(http, bot_token, db).await;
        });
    }

    // Session + sender pool
    let session = Arc::new(SqliteSession::open(&cfg.session_path)?);
    let pool = SenderPool::new(Arc::clone(&session), cfg.api_id);

    let client = Client::new(&pool);

    // Start I/O runner
    let runner = pool.runner;
    tokio::spawn(async move {
        runner.run().await;
    });

    let updates_rx = pool.updates;

    ensure_user_login(&client, &cfg).await?;

    // Resolve channels to peer IDs (so matching is fast)
    let mut allowed_peer_ids: HashSet<i64> = HashSet::new();
    for uname in &cfg.channels {
        let peer = client
            .resolve_username(uname)
            .await
            .with_context(|| format!("resolve_username failed for @{uname}"))?;
        if let Some(peer) = peer {
            allowed_peer_ids.insert(peer.id().bare_id());
            info!("Watching @{uname} (peer_id={})", peer.id().bare_id());
        }
    }

    // Update stream (ordered + gap recovery) :contentReference[oaicite:8]{index=8}
    let mut stream = client.stream_updates(
        updates_rx,
        grammers_client::UpdatesConfiguration {
            catch_up: true,
            update_queue_limit: Some(2048),
        },
    );

    let http = HttpClient::new();

    // Alert filter: threat detection + location matching + dedup.
    let mut alert_filter = filter::AlertFilter::from_env();
    info!("Filter config: {alert_filter}");

    info!("Running. Waiting for new messages...");
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

            // Run through the filter pipeline
            if let Some(formatted) = alert_filter.process(title, text) {
                info!("Alert forwarded from @{title}");
                if let Err(e) = bot::broadcast(&http, &cfg.bot_token, &bot_db, &formatted).await {
                    warn!("Failed to broadcast alert: {e}");
                }
            }
        }
    }

    Ok(())
}
