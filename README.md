# tg_osint

A Telegram OSINT tool written in Rust that monitors Ukrainian air-raid / military alert channels, filters by threat type and your location, deduplicates cross-channel noise, and forwards relevant alerts to subscribers via a Telegram bot.

## Features

- Monitors one or more public Telegram channels in real time
- **Threat detection** – classifies messages into Ballistic / Cruise Missile / Shahed / Recon Drone / Aircraft / generic threat using Ukrainian keyword stems
- **Location filtering** – only forwards alerts that mention your oblast, city, or district
- **Smart deduplication** – same threat type from multiple channels within a configurable time window is sent once; proximity upgrades (oblast → city → district) still get through
- **Bot commands** – `/start_receive` to subscribe, `/stop_receive` to unsubscribe; subscribers stored in SQLite
- Persistent Telegram user session via SQLite (no re-login on restart)
- Supports 2FA login

## Setup

1. Clone the repo and build:
   ```bash
   cargo build --release
   ```

2. Create a `.env` file in the project root:
   ```env
   # --- Telegram user client ---
   TG_API_ID=12345678
   TG_API_HASH=your_api_hash
   TG_PHONE=+380123456789
   TG_CHANNELS=air_alert_ua,kharkiv_alerts,ukraine_now
   TG_2FA_PASSWORD=your_password             # optional
   TG_SESSION_PATH=./telegram.session.sqlite  # optional

   # --- Bot ---
   BOT_TOKEN=123456:ABC-DEF...
   BOT_DB_PATH=./bot_subscribers.sqlite       # optional

   # --- Alert filter (include BOTH Ukrainian AND Russian name forms!) ---
   MY_OBLAST=Київськ,Киевск,Kyiv
   MY_CITY=Київ,Києв,Киев,Kyiv,Васильків,Васильков
   MY_DISTRICT=Шевченківськ,Шевченковск
   DEDUP_WINDOW_SECS=180                      # optional, default 180
   FORWARD_ALL_THREATS=false                   # optional, forward threats outside your area
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
| `TG_API_HASH` | ✅ | Telegram API hash |
| `TG_PHONE` | ✅ | Your phone number in international format |
| `TG_CHANNELS` | ✅ | Comma-separated list of channel usernames to monitor |
| `BOT_TOKEN` | ✅ | Telegram Bot API token from @BotFather |
| `MY_OBLAST` | ✅ | Oblast name stems — **UA + RU + EN** (e.g. `Київськ,Киевск,Kyiv`) |
| `MY_CITY` | ✅ | City name stems — **UA + RU + EN** (e.g. `Київ,Києв,Киев,Kyiv`) |
| `MY_DISTRICT` | ❌ | District name stems — **UA + RU** |
| `TG_2FA_PASSWORD` | ❌ | 2FA password if enabled on your account |
| `TG_SESSION_PATH` | ❌ | Path for the SQLite session file (default: `./telegram.session.sqlite`) |
| `BOT_DB_PATH` | ❌ | Path for the subscriber SQLite file (default: `./bot_subscribers.sqlite`) |
| `DEDUP_WINDOW_SECS` | ❌ | Dedup sliding window in seconds (default: `180`) |
| `FORWARD_ALL_THREATS` | ❌ | `true` to forward alerts even outside your area (default: `false`) |

> **Tip:** Use short stems to catch all Ukrainian/Russian declension forms.
> For example, `Київ` matches "Київ", "Києву"; `Киев` matches "Киев", "Киеву", "Киева".

## How the filter works

```
Channel message
  │
  ├─ Threat detection (UA + RU keyword stems)
  │   ├─ No threat keywords? → skip
  │   └─ "Відбій / Отбой" (all clear)?
  │       → forward immediately, clear dedup cache
  │
  ├─ Nationwide check ("по всій території України" …)
  │   └─ Nationwide? → bypass location filter, tag 🟣 ВСЯ УКРАЇНА
  │
  ├─ Location matching (district > city > oblast)
  │   └─ No location match and not nationwide? → skip (unless FORWARD_ALL_THREATS=true)
  │
  ├─ Urgency check ("повторно", "нова хвиля", "терміново" …)
  │   └─ Urgent? → forward (once per source channel, not cross-channel echo)
  │
  ├─ Dedup (same ThreatKind within DEDUP_WINDOW_SECS)
  │   ├─ Same or lower proximity? → skip
  │   └─ Proximity upgrade (oblast → city → district)? → forward
  │
  └─ Format & broadcast to all /start_receive subscribers
```

### Detected threat types

| Type | UA stems | RU stems | Emoji |
|---|---|---|---|
| Hypersonic | гіперзвук, циркон, **орєшнік** | гиперзвук, циркон, **орешник**, oreshnik | ‼️⚡ |
| Ballistic | балістик, балістичн, іскандер, кінжал, точка-у, **брсд**, **кедр**, **рс-26**, **рубіж**, міжконтинентальн, середньої дальності | баллистик, искандер, кинжал, **брсд**, **кедр**, **рс-26**, **рубеж**, межконтинентальн, средней дальности, кн-23, кн-25, фатех | ‼️🚀 |
| Cruise missile | крилат, калібр, х-101, х-555, х-22, х-59, х-69, х-35, х-31, х-55 | крылат, калибр | 🚀 |
| Guided bomb (КАБ) | керован, авіабомб, плануюч | управляем, авиабомб, планирующ, каб-500, фаб-500, умпб, умпк, jdam | 💣 |
| Shahed/drone | шахед, герань, мопед, газонокосил, ударн, бпла, безпілотник, камікадзе | мопед, беспилотник, камикадзе, мохаджер | 🔺 |
| Recon drone | розвідувальн, орлан, ланцет, елерон, фурія | разведывательн, элерон | 🛸 |
| Aircraft | авіаці, зліт, ту-95, ту-160, ту-22, міг-31, су-57, су-35, а-50, іл-76 | авиаци, взлёт, миг-31, ту-95… | ✈️ |
| Missile (generic) | ракет, пуск, запуск, ціл, курс на, летять на, с-300 | ракет, пуск, цел, летит на, направлени | 🚀 |
| All clear | відбій, загроза минула, чисте небо | отбой, угроза миновала, чистое небо | ✅ |
| Other | загроз, тривог, вибух, прильот, уламк, укриття, пожеж, кассетн | угроз, тревог, взрыв, прилёт, осколк, укрытие, пожар, громко | ⚠️ |

> **Nationwide alerts** ("по всій території України" / "по всей территории") bypass location
> filtering and are tagged 🟣 ВСЯ УКРАЇНА — everyone gets them.

## Bot commands

| Command | Description |
|---|---|
| `/start` | Show help |
| `/start_receive` | Subscribe to alerts |
| `/stop_receive` | Unsubscribe |

## Planned

- Regex keyword support
- Per-channel keyword rules
- Web dashboard

