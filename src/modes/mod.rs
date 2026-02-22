mod dump_today;
mod live;
mod replay;
mod shared;

use anyhow::Result;

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

pub async fn run_from_env() -> Result<()> {
    match RunMode::from_env() {
        RunMode::Live => live::run().await,
        RunMode::DumpToday => dump_today::run().await,
        RunMode::Replay => replay::run().await,
    }
}
