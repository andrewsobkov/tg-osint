use anyhow::{Context, Result, anyhow};
use dotenvy::dotenv;
use grammers_client::{Client, SignInError, Update};
use grammers_mtsender::SenderPool;
use grammers_session::storages::SqliteSession;
use reqwest::Client as HttpClient;
use serde::Serialize;
use std::{collections::HashSet, io::Write, sync::Arc, time::Duration};
use tokio::io::{self, AsyncBufReadExt};
use tokio::time::{MissedTickBehavior, interval};
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
    target_chat_id: i64,
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

#[derive(Serialize)]
struct SendMessageReq<'a> {
    chat_id: i64,
    text: &'a str,
    disable_web_page_preview: bool,
}

async fn bot_send_digest(http: &HttpClient, cfg: &Cfg, text: &str) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", cfg.bot_token);
    let body = SendMessageReq {
        chat_id: cfg.target_chat_id,
        text,
        disable_web_page_preview: true,
    };

    let resp = http.post(url).json(&body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let raw = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Bot API sendMessage failed: {status} body={raw}"));
    }
    Ok(())
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
        target_chat_id: must_env("TARGET_CHAT_ID")?
            .parse()
            .context("TARGET_CHAT_ID must be i64")?,
    };

    if cfg.channels.is_empty() {
        return Err(anyhow!("TG_CHANNELS is empty"));
    }

    // Session + sender pool
    let session = Arc::new(SqliteSession::open(&cfg.session_path)?); // recommended storage :contentReference[oaicite:3]{index=3}
    let pool = SenderPool::new(Arc::clone(&session), cfg.api_id); // provides updates receiver :contentReference[oaicite:4]{index=4}

    // Create client before moving fields out of pool
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
    let mut tick = interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut buffer: Vec<String> = Vec::new();

    info!("Running. Waiting for new messages...");
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if buffer.is_empty() {
                    continue;
                }

                // Keep it safely under Telegram 4096 limit
                let mut out = String::new();
                for (i, item) in buffer.iter().enumerate() {
                    if i > 0 { out.push_str("\n\n"); }
                    if out.len() + item.len() + 2 > 3500 { // conservative
                        out.push_str("\n\n…(truncated)");
                        break;
                    }
                    out.push_str(item);
                }
                buffer.clear();

                if let Err(e) = bot_send_digest(&http, &cfg, &out).await {
                    warn!("Failed to send digest: {e}");
                }
            }

            maybe = stream.next() => {
                let Ok(update) = maybe else {
                    warn!("Update stream ended.");
                    break;
                };

                if let Update::NewMessage(msg) = update {

                    // let Channel(p) =  msg.peer.id else {
                    //     continue; // only care about channel posts for now
                    // };
                    // Only channel posts / messages that belong to the watched peers
                    let Ok(peer) = msg.peer() else {
                        continue;
                    };
                    info!("Received new message update: peer_id={:?}", peer.id().bare_id());
                    if !allowed_peer_ids.contains(&peer.id().bare_id()) {
                            continue;
                    }
                    info!("Received new message update: message={:?}", msg);
                    // if let Some(chat) = msg.chat() {
                    //     let pid = chat.id();
                    //     if !allowed_peer_ids.contains(&pid) {
                    //         continue;
                    //     }

                    //     let text = msg.text().trim();
                    //     if text.is_empty() {
                    //         continue;
                    //     }

                    //     // Simple formatting for v0
                    //     let title = chat.name().unwrap_or("<chat>");
                    //     let line = format!("🛰️ {title}\n{text}");
                    //     buffer.push(line);
                    // }
                }
            }
        }
    }

    Ok(())
}
