# Context Window Feature Implementation

## Summary

This document describes the implementation of a per-channel context window system for better threat categorization and **location-aware inference** in the Telegram OSINT bot.

## Problem Statement

The word "ціль" (Ukrainian) / "цель" (Russian) means "target" or "goal" and is commonly used in military alerts to indicate incoming missiles ("2 цілі на Київ" = "2 targets toward Kyiv"). However, this word is ambiguous and can also appear in non-alert contexts ("досягти цілі операції" = "achieve the operation's goal").

Additionally, alert channels often split information across multiple messages:
- Message 1: threat type without a destination ("вихід балістики" = ballistic launch)
- Message 2: destination without threat type ("на Київ" = toward Kyiv)
- Message 3: urgency update ("повторно" = repeated)

Without context, each message alone is insufficient to generate a useful alert.

Previously, these keywords were included in the generic `Missile` category, which led to:
- False positives on analytical text
- Loss of specificity (couldn't distinguish ballistic from cruise missiles from drones)
- Missed alerts when threat and location arrive in separate messages

## Solution

### 1. Remove "ціль"/"цель" from Generic Keywords

**Changed in:** `src/filter/mod.rs`

Removed the following keywords from `ThreatKind::Missile`:
- `ціль` (UA: target)
- `цілі` (UA: targets)
- `цілей` (UA: of targets)
- `цель` (RU: target)
- `цели` (RU: targets)
- `целей` (RU: of targets)

### 2. Per-Channel Context Window System

**Added in:** `src/filter/mod.rs`

New data structures:
```rust
struct ContextMessage {
    timestamp: Instant,
    text_lower: String,
    detected_threats: Vec<ThreatKind>,
    detected_proximity: Proximity,
}

struct ChannelContext {
    messages: Vec<ContextMessage>,
    window_duration: Duration,
}

struct ContextDetection {
    threats: Vec<ThreatKind>,
    proximity: Proximity,
    nationwide: bool,
}
```

Each channel maintains a sliding window of recent messages (default 5 minutes, configurable via `CONTEXT_WINDOW_SECS`).

### 3. Context-Based Threat and Location Inference

When a message arrives, the system performs **five inference steps**:

1. **Trigger-word inference** ("ціль", "вихід", etc.) — when no explicit threat keyword is present, looks back through context to determine the threat type
2. **Location → Threat** — location keyword present but no threat → infer threat from context
3. **Urgent → Threat** — urgency keyword present but no threat → infer threat from context
4. **Threat → Location** — threat keyword present but no location → infer location from context
5. **Urgent → Location** — urgency keyword present but no location → infer location from context

Messages are **always stored in context** (even when not forwarded) so that future messages can infer from them.

### 4. Channel Isolation

Each channel has its own independent context window. This prevents:
- Cross-channel contamination (Channel A discussing ballistics doesn't affect Channel B's drone alerts)
- Confusion between different alert sources with different focus areas

### 5. AllClear Resets Context

When "відбій" (all-clear) is received, both the dedup cache and all channel contexts are cleared, preventing stale threats from being inferred into the next wave.

## Configuration

Environment variable:

```bash
CONTEXT_WINDOW_SECS=300  # default: 5 minutes
```

Messages older than this duration are automatically evicted from the context window.

## Examples

### Example 1: Threat Without Location → Location Follow-up

```
Message 1 (Channel @alerts_ua, 10:00):
"вихід балістики"
→ Detected: Ballistic (no location → not forwarded, but seeds context)

Message 2 (Channel @alerts_ua, 10:02):
"на Київ"
→ Detected: no threat keywords, but Київ = City location
→ Context inferred: Ballistic (from Message 1)
→ Alert: ‼️🚀 Балістика · 🟠 МІСТО
→ FORWARDED
```

### Example 2: Multi-Channel Dedup with Context

```
Channel 1: "вихід балістики"     → no location, not forwarded (seeds context)
Channel 2: "балістика брянськ"   → брянськ not in user config, not forwarded (seeds context)
Channel 1: "на Київ"             → infer Ballistic from ch1 context → FORWARD
Channel 2: "вектором на Київ"    → infer Ballistic from ch2 context → DEDUP (same threat+location)
Channel 1: "2 цілі на Київ"     → infer Ballistic from trigger → DEDUP
Channel 2: "повторно"            → urgent, infer Ballistic+City from ch2 context → FORWARD
Channel 1: "повторні виходи"     → urgent echo from different channel → DEDUP
```

### Example 3: Channel Isolation

```
Channel A (Military):
- 08:00: "балістична загроза" → context: Ballistic
- 08:05: "ціль на Київ" → infers: Ballistic ✓

Channel B (Civil):
- 08:02: "шахеди в повітрі" → context: Shahed
- 08:06: "ціль на Київ" → infers: Shahed ✓ (not Ballistic!)
```

### Example 4: Urgent Infers Both Threat and Location

```
Message 1 (10:00): "балістика на Київ" → FORWARD (Ballistic, City)
Message 2 (10:03): "повторно"          → infers Ballistic + City from context → FORWARD (urgent)
```

## Implementation Details

### Modified Functions

1. **`AlertFilter::from_env()`** — Added `channel_contexts: HashMap::new()`
2. **`AlertFilter::process_with_id()`** — Uses `detect_with_context()` which handles both threat and location
3. **`AlertFilter::process_with_llm()`** — Same restructuring; context seeded before LLM call
4. **`AlertFilter::try_all_clear()`** — Now also clears `channel_contexts`

### New Structures

1. **`ContextDetection`** — Result of context-aware detection (threats + proximity + nationwide)

### New/Modified Functions

1. **`ChannelContext::add()`** — Now accepts `Proximity` parameter
2. **`ChannelContext::infer_threat_from_triggers()`** — Renamed from `infer_target_threat()`, expanded triggers
3. **`ChannelContext::infer_recent_threat()`** — Infer threat from recent context (no trigger needed)
4. **`ChannelContext::infer_location()`** — Infer proximity from recent context
5. **`AlertFilter::detect_with_context()`** — Rewritten with 5-step inference pipeline

### Urgency Keywords Expanded

- `"повторн"` stem (covers повторно, повторні, повторна, повторних)
- `"ще вихо"` (covers ще виходи, ще вихід — more launches)

### Test Coverage

Existing tests:
- `context_infers_ballistic_from_recent_message`
- `context_infers_cruise_missile_from_recent_message`
- `context_infers_shahed_from_dron_keyword`
- `context_separate_per_channel`
- `context_defaults_to_missile_without_history`
- `context_tsel_without_trigger_does_not_alert`

New tests:
- `context_location_only_infers_threat` — location without threat infers from context
- `context_threat_infers_location` — threat without location infers from context
- `context_urgent_infers_both_threat_and_location` — "повторно" alone infers both
- `context_launch_trigger_infers_threat` — "виходи" triggers inference
- `context_multichannel_scenario` — full 7-step scenario from requirements
- `context_all_clear_resets_context` — AllClear prevents stale inference
- `context_urgency_povtorni` — "повторні" matches urgency
- `context_urgency_shche_vykho` — "ще виходи" matches urgency

## Performance Considerations

- **Memory**: Each channel stores max 20 messages (configurable)
- **CPU**: O(1) hash lookup per channel, O(n) context scan where n ≤ 20
- **Cleanup**: Automatic eviction on every message processing

## Future Enhancements

1. **Velocity inference**: Track time between updates to estimate speed
   - Ballistic: very fast
   - Cruise missile: subsonic
   - Shahed: slow (lawnmower speed)

2. **Multi-hop context**: Link related messages across channels
   - Different regional channels reporting same threat wave

3. **LLM context injection**: Pass recent context to LLM for better verification

## Rollout Notes

- **Backward compatible**: Existing behavior unchanged when "ціль" not present
- **Fail-safe**: Defaults to generic `Missile` if context unavailable
- **No breaking changes**: All existing tests pass (updated for new field)

## Related Files

- `src/filter/mod.rs` — Main implementation
- `src/filter/threat_keywords.rs` — Keyword lists (urgency expanded)
- `src/filter/filter_tests.rs` — Tests
- `src/main.rs` — Integration point