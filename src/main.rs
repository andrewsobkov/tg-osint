mod bot;
mod filter;
mod llm;
mod modes;
mod telegram;

use anyhow::Result;
use dotenvy::dotenv;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt().with_target(false).init();
    modes::run_from_env().await
}
