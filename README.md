# tg_osint

A Telegram OSINT tool written in Rust that monitors public channels for keyword matches and logs alerts to the console for now.

## Features

- Monitors one or more public Telegram channels in real time
- Keyword-based filtering with case-insensitive substring matching
- Logs matched messages to the console
- Persistent session via SQLite (no re-login on restart)
- Supports 2FA login

## Requirements

- Rust (stable)
- A Telegram account with API credentials from [my.telegram.org](https://my.telegram.org)

## Setup

1. Clone the repo and build:
   ```bash
   cargo build --release
   ```

2. Create a `.env` file in the project root:
   ```env
   TG_API_ID=12345678
   TG_API_HASH=your_api_hash
   TG_PHONE=+1234567890
   TG_CHANNELS=channel1,channel2
   TG_KEYWORDS=ukraine,nato,missile     # optional; omit to log all messages
   TG_2FA_PASSWORD=your_password        # optional; only if 2FA is enabled
   TG_SESSION_PATH=./telegram.session.sqlite  # optional; default shown
   ```

3. Run:
   ```bash
   cargo run
   ```

   On first run you will be prompted to enter the login code sent to your Telegram account.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `TG_API_ID` | ✅ | Telegram API ID from my.telegram.org |
| `TG_API_HASH` | ✅ | Telegram API hash from my.telegram.org |
| `TG_PHONE` | ✅ | Your phone number in international format |
| `TG_CHANNELS` | ✅ | Comma-separated list of channel usernames to monitor |
| `TG_KEYWORDS` | ❌ | Comma-separated keywords to filter messages |
| `TG_2FA_PASSWORD` | ❌ | 2FA password if enabled on your account |
| `TG_SESSION_PATH` | ❌ | Path for the SQLite session file (default: `./telegram.session.sqlite`) |

## Planned

- Telegram bot digest / alert forwarding
- Regex keyword support
- Per-channel keyword rules
