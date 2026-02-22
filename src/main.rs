mod bot;
mod filter;
mod llm;

use anyhow::{Context, Result, anyhow};
use chrono::{FixedOffset, TimeZone, Utc};
use dotenvy::dotenv;
use grammers_client::{Client, SignInError, Update};
use grammers_mtsender::SenderPool;
use grammers_session::storages::SqliteSession;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::io::{self, AsyncBufReadExt};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Live,
    DumpToday,
    Replay,
}

impl RunMode {
    fn from_env() -> Self {
        let raw = std::env::var("RUN_MODE").unwrap_or_else(|_| "live".into());
        match raw.trim().to_lowercase().as_str() {
            "dump_today" | "dump" => Self::DumpToday,
            "replay" => Self::Replay,
            _ => Self::Live,
        }
    }
}

#[derive(Clone)]
struct TgCfg {
    api_id: i32,
    api_hash: String,
    phone: String,
    two_fa_password: Option<String>,
    session_path: String,
    channels: Vec<String>,
}

#[derive(Clone)]
struct BotCfg {
    token: String,
    db_path: String,
}

#[derive(Clone)]
struct ReplayCfg {
    input_path: String,
    speed: f64,
    fixed_step_ms: Option<u64>,
    min_delay_ms: u64,
    max_delay_ms: u64,
    broadcast: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DumpEvent {
    timestamp: i64,
    channel_id: i64,
    channel_title: String,
    text: String,
}

fn must_env(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow!("Missing env var {key}"))
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(default)
}

fn parse_channels(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().trim_start_matches('@'))
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect()
}

fn load_tg_cfg() -> Result<TgCfg> {
    let channels = parse_channels(&must_env("TG_CHANNELS")?);
    if channels.is_empty() {
        return Err(anyhow!("TG_CHANNELS is empty"));
    }

    Ok(TgCfg {
        api_id: must_env("TG_API_ID")?
            .parse()
            .context("TG_API_ID must be i32")?,
        api_hash: must_env("TG_API_HASH")?,
        phone: must_env("TG_PHONE")?,
        two_fa_password: std::env::var("TG_2FA_PASSWORD").ok(),
        session_path: std::env::var("TG_SESSION_PATH")
            .unwrap_or_else(|_| "./telegram.session.sqlite".into()),
        channels,
    })
}

fn load_bot_cfg() -> Result<BotCfg> {
    Ok(BotCfg {
        token: must_env("BOT_TOKEN")?,
        db_path: std::env::var("BOT_DB_PATH").unwrap_or_else(|_| "./bot_subscribers.sqlite".into()),
    })
}

fn load_replay_cfg() -> Result<ReplayCfg> {
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

async fn read_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let mut stdin = io::BufReader::new(io::stdin());
    stdin.read_line(&mut line).await?;
    Ok(line.trim().to_string())
}

async fn ensure_user_login(client: &Client, cfg: &TgCfg) -> Result<()> {
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

fn start_of_today_utc_from_offset(offset_minutes: i32) -> Result<i64> {
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

async fn run_dump_today() -> Result<()> {
    let tg = load_tg_cfg()?;
    let output_path =
        std::env::var("DUMP_OUTPUT_PATH").unwrap_or_else(|_| "./dump_today.jsonl".into());
    let offset_minutes = std::env::var("DUMP_TZ_OFFSET_MINUTES")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);
    let now_ts = Utc::now().timestamp();
    let since_ts = start_of_today_utc_from_offset(offset_minutes)?;

    let session = Arc::new(SqliteSession::open(&tg.session_path)?);
    let pool = SenderPool::new(Arc::clone(&session), tg.api_id);
    let client = Client::new(&pool);

    let runner = pool.runner;
    tokio::spawn(async move {
        runner.run().await;
    });

    ensure_user_login(&client, &tg).await?;

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

fn load_dump_events(path: &str) -> Result<Vec<DumpEvent>> {
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

async fn run_replay() -> Result<()> {
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

async fn run_live() -> Result<()> {
    let tg = load_tg_cfg()?;
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

    let session = Arc::new(SqliteSession::open(&tg.session_path)?);
    let pool = SenderPool::new(Arc::clone(&session), tg.api_id);
    let client = Client::new(&pool);

    let runner = pool.runner;
    tokio::spawn(async move {
        runner.run().await;
    });

    let updates_rx = pool.updates;

    ensure_user_login(&client, &tg).await?;

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

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt().with_target(false).init();

    match RunMode::from_env() {
        RunMode::Live => run_live().await,
        RunMode::DumpToday => run_dump_today().await,
        RunMode::Replay => run_replay().await,
    }
}
