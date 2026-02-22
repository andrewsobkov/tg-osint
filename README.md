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
   CONTEXT_WINDOW_SECS=300                    # optional, default 300 (5 min)
   URGENT_COOLDOWN_SECS=20                    # optional, same-channel urgent re-alert cooldown
   NEGATIVE_STATUS_COOLDOWN_SECS=120          # optional, one-time "не фіксуються" status cooldown
   FORWARD_ALL_THREATS=false                  # optional, forward threats outside your area
   ```

3. Run:
   ```bash
   cargo run
   ```

   On first run you will be prompted to enter the login code sent to your Telegram account.

## Run Modes

`RUN_MODE` controls execution mode:

- `live` (default): current behavior, listen to Telegram updates and broadcast alerts.
- `dump_today`: fetch today history from `TG_CHANNELS` and write it to JSONL.
- `replay`: read JSONL dump and replay messages through the same filter pipeline without Telegram user connection.

### 1) Dump today's history

```bash
RUN_MODE=dump_today \
DUMP_OUTPUT_PATH=./dumps/2026-02-22.jsonl \
DUMP_TZ_OFFSET_MINUTES=120 \
cargo run
```

`DUMP_TZ_OFFSET_MINUTES` defines what "today" means (for Ukraine use `120` in winter, `180` in summer).

### 2) Replay offline

```bash
RUN_MODE=replay \
REPLAY_INPUT_PATH=./dumps/2026-02-22.jsonl \
REPLAY_SPEED=10 \
cargo run
```

Replay only a fragment (for example lines 308..434 from a JSONL dump):

```bash
RUN_MODE=replay \
REPLAY_INPUT_PATH=./dumps/2026-02-22.jsonl \
REPLAY_FROM_LINE=308 \
REPLAY_TO_LINE=434 \
REPLAY_SPEED=100 \
cargo run
```

Replay timing options:

- `REPLAY_SPEED` (default `1.0`): `10` means 10x faster than original timing.
- `REPLAY_STEP_MS`: fixed delay between all events (overrides timestamp-based replay).
- `REPLAY_MIN_DELAY_MS` (default `0`) and `REPLAY_MAX_DELAY_MS` (default `10000`): clamp replay delays.
- `REPLAY_BROADCAST` (default `false`): if `true`, replayed alerts are sent via bot subscribers; otherwise printed to stdout.
- `REPLAY_FROM_LINE` / `REPLAY_TO_LINE`: 1-based inclusive line range in input JSONL.
- `REPLAY_LIMIT`: maximum number of events to load after line filtering.

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
| `CONTEXT_WINDOW_SECS` | ❌ | Per-channel context window for threat inference in seconds (default: `300`) |
| `URGENT_COOLDOWN_SECS` | ❌ | Minimum delay for same-channel urgent re-alerts (default: `20`) |
| `NEGATIVE_STATUS_COOLDOWN_SECS` | ❌ | Per-channel cooldown for one-time negative status updates (default: `120`) |
| `FORWARD_ALL_THREATS` | ❌ | `true` to forward alerts even outside your area (default: `false`) |
| `LLM_ENABLED` | ❌ | `true` to enable LLM secondary filter (default: `false`) |
| `LLM_MODEL` | ❌ | Ollama model name (default: `qwen2.5:7b`) |
| `LLM_ENDPOINT` | ❌ | Ollama / llama-server base URL (default: `http://127.0.0.1:11434`) |
| `LLM_TIMEOUT_MS` | ❌ | LLM request timeout in milliseconds (default: `3000`) |
| `RUN_MODE` | ❌ | `live` (default), `dump_today`, or `replay` |
| `DUMP_OUTPUT_PATH` | ❌ | Output JSONL file for `RUN_MODE=dump_today` (default: `./dump_today.jsonl`) |
| `DUMP_TZ_OFFSET_MINUTES` | ❌ | Timezone offset for defining "today" in dump mode (default: `0`) |
| `REPLAY_INPUT_PATH` | ✅ for replay | JSONL file path used by `RUN_MODE=replay` |
| `REPLAY_SPEED` | ❌ | Replay speed multiplier (default: `1.0`) |
| `REPLAY_STEP_MS` | ❌ | Fixed replay delay per event in ms (overrides speed) |
| `REPLAY_MIN_DELAY_MS` | ❌ | Minimum delay in ms for timestamp replay (default: `0`) |
| `REPLAY_MAX_DELAY_MS` | ❌ | Maximum delay in ms for timestamp replay (default: `10000`) |
| `REPLAY_BROADCAST` | ❌ | `true` to send replay alerts via bot, otherwise stdout (default: `false`) |
| `REPLAY_FROM_LINE` | ❌ | 1-based start line (inclusive) to replay from JSONL |
| `REPLAY_TO_LINE` | ❌ | 1-based end line (inclusive) to replay from JSONL |
| `REPLAY_LIMIT` | ❌ | Max loaded events after line filtering |

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
  ├─ 🤖 LLM verification (optional, LLM_ENABLED=true)
  │   ├─ Confirms / removes keyword-detected threats
  │   └─ Fail-open: on timeout/error, keyword result used as-is
  │
  ├─ Urgency check ("повторно", "нова хвиля", "терміново" …)
  │   └─ Urgent? → forward (not cross-channel echo; same-channel repeats throttled by URGENT_COOLDOWN_SECS)
  │
  ├─ Dedup (same primary ThreatKind within DEDUP_WINDOW_SECS)
  │   ├─ Same or lower proximity? → skip
  │   └─ Proximity upgrade OR first nationwide OR new threat combination? → forward
  │
  └─ Format & broadcast to all /start_receive subscribers
```

## LLM secondary filter (optional)

A local LLM can verify keyword-detected threats and suppress false positives
(e.g. analytical reports that mention "пускові зони" triggering a missile alert).

Uses [Ollama](https://ollama.com/) — one-command install, auto GPU detection, no manual model downloads.

### Model recommendation

| Model | VRAM / RAM | Speed (RTX 3060) | UA/RU quality | Best for |
|---|---|---|---|---|
| **`qwen2.5:7b`** ⭐ | ~4.5 GB VRAM | ~0.5s | ★★★★★ | GPU with ≥6 GB VRAM |
| `qwen2.5:3b` | ~2 GB RAM | ~0.3s | ★★★★ | CPU-only / low RAM |
| `gemma2:9b` | ~6 GB VRAM | ~0.8s | ★★★★ | Alternative if Qwen has issues |
| `llama3.1:8b` | ~5 GB VRAM | ~0.5s | ★★★ | English-heavy, weaker on UA |
| `mistral:7b` | ~4.5 GB VRAM | ~0.5s | ★★★ | Weaker on Ukrainian |

**Why Qwen 2.5?** Strongest multilingual model at 7B — trained with extensive Cyrillic data, benchmarks highest on Ukrainian/Russian text understanding among models that fit in 6 GB VRAM.

### Setup

1. Install Ollama:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. Pull the model:
   ```bash
   ollama pull qwen2.5:7b          # GPU (~4.5 GB)
   # OR for CPU-only / low RAM:
   ollama pull qwen2.5:3b          # CPU (~2 GB)
   ```

3. Enable in `.env`:
   ```env
   LLM_ENABLED=true
   LLM_MODEL=qwen2.5:7b                      # default
   LLM_ENDPOINT=http://127.0.0.1:11434        # default (Ollama)
   LLM_TIMEOUT_MS=3000                         # default
   ```

Or use the helper script:
```bash
chmod +x run_llm_server.sh
./run_llm_server.sh          # pulls model + verifies
./run_llm_server.sh --3b     # use smaller 3B model
```

### How it works

- Keywords detect candidate threats (fast, <1ms)
- LLM verifies: "is this an **active** alert or analytical text?" (<1s on GPU)
- LLM can only **remove** threats, never add new ones
- On timeout/error → keyword result used as-is (**fail-open** for safety)
- AllClear messages bypass LLM entirely (no latency on threat cessation)

### Alternative: llama.cpp

If you prefer raw llama.cpp over Ollama:
```bash
llama-server --model qwen2.5-7b-instruct-q4_k_m.gguf --port 8012 --n-gpu-layers 99 --ctx-size 2048
```
```env
LLM_ENDPOINT=http://127.0.0.1:8012
LLM_MODEL=qwen2.5
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
| Missile (generic) | ракет, запуск, ціль/цілі/цілей, курс на, летять на, с-300 | ракет, запуск, цель/цели/целей, летит на, с-300 | 🚀 |
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
