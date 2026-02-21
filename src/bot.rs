//! Bot management: subscriber store (SQLite), long-poll loop, broadcast helper.

use anyhow::{Result, anyhow};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sqlite::State;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Shared database handle
// ---------------------------------------------------------------------------

pub type SharedDb = Arc<Mutex<sqlite::Connection>>;

/// Open (or create) the subscriber database and ensure the schema exists.
pub fn open_db(path: &str) -> Result<SharedDb> {
    let conn = sqlite::open(path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS subscribers (
            chat_id  INTEGER PRIMARY KEY,
            added_at TEXT    NOT NULL DEFAULT (datetime('now'))
         );",
    )?;
    info!("Subscriber DB opened at {path}");
    Ok(Arc::new(Mutex::new(conn)))
}

pub fn add_subscriber(db: &SharedDb, chat_id: i64) -> Result<()> {
    let db = db.lock().unwrap();
    let mut stmt = db.prepare("INSERT OR IGNORE INTO subscribers (chat_id) VALUES (?)")?;
    stmt.bind((1, chat_id))?;
    stmt.next()?;
    Ok(())
}

pub fn remove_subscriber(db: &SharedDb, chat_id: i64) -> Result<()> {
    let db = db.lock().unwrap();
    let mut stmt = db.prepare("DELETE FROM subscribers WHERE chat_id = ?")?;
    stmt.bind((1, chat_id))?;
    stmt.next()?;
    Ok(())
}

pub fn get_subscribers(db: &SharedDb) -> Result<Vec<i64>> {
    let db = db.lock().unwrap();
    let mut stmt = db.prepare("SELECT chat_id FROM subscribers")?;
    let mut ids = Vec::new();
    while let Ok(State::Row) = stmt.next() {
        ids.push(stmt.read::<i64, _>(0)?);
    }
    Ok(ids)
}

// ---------------------------------------------------------------------------
// Bot API types (getUpdates)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GetUpdatesResponse {
    ok: bool,
    result: Vec<TgUpdate>,
}

#[derive(Deserialize)]
struct TgUpdate {
    update_id: i64,
    message: Option<TgMessage>,
}

#[derive(Deserialize)]
struct TgMessage {
    chat: TgChat,
    text: Option<String>,
}

#[derive(Deserialize)]
struct TgChat {
    id: i64,
}

// ---------------------------------------------------------------------------
// Sending helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SendMessagePayload<'a> {
    chat_id: i64,
    text: &'a str,
    disable_web_page_preview: bool,
}

/// Send a single message to one chat via the Bot API.
pub async fn send_message(
    http: &HttpClient,
    bot_token: &str,
    chat_id: i64,
    text: &str,
) -> Result<()> {
    let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
    let body = SendMessagePayload {
        chat_id,
        text,
        disable_web_page_preview: true,
    };
    let resp = http.post(&url).json(&body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let raw = resp.text().await.unwrap_or_default();
        return Err(anyhow!("sendMessage failed: {status} body={raw}"));
    }
    Ok(())
}

/// Broadcast `text` to every active subscriber.
pub async fn broadcast(
    http: &HttpClient,
    bot_token: &str,
    db: &SharedDb,
    text: &str,
) -> Result<()> {
    let subscribers = get_subscribers(db)?;
    if subscribers.is_empty() {
        info!("Broadcast skipped – no subscribers.");
        return Ok(());
    }
    info!("Broadcasting to {} subscriber(s).", subscribers.len());
    for chat_id in subscribers {
        if let Err(e) = send_message(http, bot_token, chat_id, text).await {
            warn!("Failed to deliver to chat_id={chat_id}: {e}");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Long-poll loop
// ---------------------------------------------------------------------------

/// Runs forever: polls `getUpdates` and handles /start_receive / /stop_receive.
pub async fn run_bot_polling(http: HttpClient, bot_token: String, db: SharedDb) {
    let mut offset: i64 = 0;
    info!("Bot long-poll loop started.");

    loop {
        let url = format!(
            "https://api.telegram.org/bot{bot_token}/getUpdates\
             ?timeout=30&offset={offset}&allowed_updates=[\"message\"]"
        );

        let resp = match tokio::time::timeout(Duration::from_secs(40), http.get(&url).send()).await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!("getUpdates HTTP error: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(_elapsed) => {
                warn!("getUpdates request timed out locally – retrying");
                continue;
            }
        };

        let updates: GetUpdatesResponse = match resp.json().await {
            Ok(u) => u,
            Err(e) => {
                warn!("Failed to deserialize getUpdates response: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        if !updates.ok {
            warn!("getUpdates returned ok=false");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        for update in updates.result {
            offset = update.update_id + 1;

            let Some(msg) = update.message else {
                continue;
            };

            let chat_id = msg.chat.id;
            let raw_text = msg.text.unwrap_or_default();
            // Strip optional @BotName suffix (e.g. /start_receive@MyBot)
            let cmd = raw_text.trim().split('@').next().unwrap_or("").trim();

            match cmd {
                "/start" => {
                    let _ = send_message(
                        &http,
                        &bot_token,
                        chat_id,
                        "👋 Hello!\n\
                         /start_receive – subscribe to channel updates\n\
                         /stop_receive  – unsubscribe",
                    )
                    .await;
                }

                "/start_receive" => {
                    info!("chat_id={chat_id} → subscribe");
                    match add_subscriber(&db, chat_id) {
                        Ok(_) => {
                            let _ = send_message(
                                &http,
                                &bot_token,
                                chat_id,
                                "✅ Subscribed! You will now receive channel updates.",
                            )
                            .await;
                        }
                        Err(e) => warn!("add_subscriber({chat_id}): {e}"),
                    }
                }

                "/stop_receive" => {
                    info!("chat_id={chat_id} → unsubscribe");
                    match remove_subscriber(&db, chat_id) {
                        Ok(_) => {
                            let _ = send_message(
                                &http,
                                &bot_token,
                                chat_id,
                                "🛑 Unsubscribed. You will no longer receive updates.",
                            )
                            .await;
                        }
                        Err(e) => warn!("remove_subscriber({chat_id}): {e}"),
                    }
                }

                _ => {}
            }
        }
    }
}
