use anyhow::{Context, Result, anyhow};
use grammers_client::{Client, SignInError};
use grammers_mtsender::SenderPool;
use grammers_session::storages::SqliteSession;
use std::io::Write;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt};
use tracing::info;

#[derive(Clone)]
pub struct TgCfg {
    pub api_id: i32,
    pub api_hash: String,
    pub phone: String,
    pub two_fa_password: Option<String>,
    pub session_path: String,
    pub channels: Vec<String>,
}

pub fn load_tg_cfg() -> Result<TgCfg> {
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

pub fn connect(cfg: &TgCfg) -> Result<(Client, SenderPool)> {
    let session = Arc::new(SqliteSession::open(&cfg.session_path)?);
    let pool = SenderPool::new(Arc::clone(&session), cfg.api_id);
    let client = Client::new(&pool);
    Ok((client, pool))
}

pub async fn ensure_user_login(client: &Client, cfg: &TgCfg) -> Result<()> {
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
