//! Secondary LLM-based filter that verifies keyword-detected threats.
//!
//! Uses a local [Ollama](https://ollama.com/) server (OpenAI-compatible API)
//! running **Qwen 2.5 7B**.  On timeout or error the keyword result is
//! returned unchanged (fail-open for safety).
//!
//! # Setup
//!
//! 1. Install Ollama: <https://ollama.com/download>
//!
//! 2. Pull the model:
//!    ```bash
//!    ollama pull qwen2.5:7b          # GPU, ~4.5 GB VRAM
//!    # OR for CPU-only / low RAM:
//!    ollama pull qwen2.5:3b          # ~2 GB RAM
//!    ```
//!
//! 3. Ollama runs automatically as a service after install.
//!    Verify: `curl http://localhost:11434/v1/models`
//!
//! 4. Set env vars:
//!    ```env
//!    LLM_ENABLED=true
//!    LLM_MODEL=qwen2.5:7b                      # default
//!    LLM_ENDPOINT=http://127.0.0.1:11434        # default (Ollama)
//!    LLM_TIMEOUT_MS=3000                         # default
//!    ```
//!
//! # Alternative: llama.cpp server
//!
//! If you prefer llama.cpp instead of Ollama, just change the endpoint:
//! ```env
//! LLM_ENDPOINT=http://127.0.0.1:8012
//! LLM_MODEL=qwen2.5
//! ```

use crate::filter::{Proximity, ThreatKind};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

// ─────────────────────────── System prompt ────────────────────────────────

const SYSTEM_PROMPT: &str = r#"You are a Ukrainian air-raid alert classifier.

You receive a Telegram message (Ukrainian or Russian) from an alert channel, together with a keyword-based threat guess produced by an automated filter.

Your job: decide which threats represent an ACTIVE, ONGOING, or IMMINENT threat RIGHT NOW versus analytical / historical / forecast / news / recap text.

Rules:
- Only include a threat if the message describes something happening NOW or about to happen (launch detected, drones in flight, missiles heading to a region, etc.).
- Remove threats that were triggered by analytical context (e.g. "пускові зони" is about launch zones in general, not an active launch).
- If the message is purely informational, a recap, statistics, a forecast, or a calm situation report, return an empty threats list.
- Do NOT add threats that the keyword filter missed — only confirm or remove.
- AllClear ("відбій"/"отбой") should always be confirmed if the message genuinely announces threat cessation.
- When in doubt, confirm the keyword guess (better safe than sorry)
- Do not categorize potecial threats, only factual

Reply ONLY with a JSON object, nothing else:
{"threats": ["Ballistic", ...], "reasoning": ["one sentence why for every choise",..]}

Valid threat values: Ballistic, Hypersonic, CruiseMissile, GuidedBomb, Missile, Shahed, ReconDrone, Aircraft, AllClear
Empty list = not an active alert: {"threats": [], "reasoning": ["..."]}
"#;

// ─────────────────────────── Data types ──────────────────────────────────

#[derive(Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Serialize)]
struct ResponseFormat {
    r#type: &'static str,
}

#[derive(Deserialize, Debug)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize, Debug)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Deserialize, Debug)]
struct ChoiceMessage {
    content: String,
}

#[derive(Deserialize)]
struct LlmResult {
    threats: Vec<String>,
    #[serde(default)]
    reasoning: Vec<String>,
}

// ─────────────────────────── LlmFilter ───────────────────────────────────

/// Async LLM verifier.  Constructed once, reused for every message.
pub struct LlmFilter {
    client: Client,
    endpoint: String,
    model: String,
    enabled: bool,
    timeout: Duration,
}

impl LlmFilter {
    /// Build from environment variables.
    ///
    /// | Env var          | Default                    | Description                 |
    /// |------------------|----------------------------|-----------------------------|
    /// | `LLM_ENABLED`    | `false`                    | Enable LLM secondary filter |
    /// | `LLM_MODEL`      | `qwen2.5:7b`               | Ollama model name           |
    /// | `LLM_ENDPOINT`   | `http://127.0.0.1:11434`   | Ollama / llama-server URL   |
    /// | `LLM_TIMEOUT_MS` | `3000`                     | Request timeout in ms       |
    pub fn from_env() -> Self {
        let enabled = std::env::var("LLM_ENABLED")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let endpoint =
            std::env::var("LLM_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:11434".into());

        let model = std::env::var("LLM_MODEL").unwrap_or_else(|_| "qwen2.5:7b".into());

        let timeout_ms: u64 = std::env::var("LLM_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3000);

        Self {
            client: Client::new(),
            endpoint,
            model,
            enabled,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Returns `true` when the LLM filter is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Ask the LLM to verify / correct the keyword-detected threats.
    ///
    /// On any error (timeout, server down, parse failure) the original
    /// `keyword_threats` are returned unchanged (**fail-open**).
    pub async fn verify(
        &self,
        text: &str,
        keyword_threats: &[ThreatKind],
        proximity: Proximity,
        nationwide: bool,
    ) -> Vec<ThreatKind> {
        if !self.enabled {
            return keyword_threats.to_vec();
        }

        let threats_str: String = keyword_threats
            .iter()
            .map(|t| t.variant_name())
            .collect::<Vec<_>>()
            .join(", ");

        // Truncate to ~800 chars to keep prompt short and inference fast.
        let truncated = if text.len() > 800 { &text[..800] } else { text };

        let user_content = format!(
            "Message from channel:\n```\n{truncated}\n```\n\
             Keyword filter detected: [{threats_str}]\n\
             Proximity: {prox}\n\
             Nationwide: {nationwide}\n\n\
             Classify:",
            prox = match proximity {
                Proximity::District => "District",
                Proximity::City => "City",
                Proximity::Oblast => "Oblast",
                Proximity::None => "None",
            },
        );

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: SYSTEM_PROMPT.into(),
                },
                ChatMessage {
                    role: "user",
                    content: user_content,
                },
            ],
            temperature: 0.0,
            max_tokens: 150,
            response_format: Some(ResponseFormat {
                r#type: "json_object",
            }),
        };

        let url = format!("{}/v1/chat/completions", self.endpoint);

        let result = self
            .client
            .post(&url)
            .timeout(self.timeout)
            .json(&request)
            .send()
            .await;

        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                warn!("LLM request failed (fail-open): {e}");
                return keyword_threats.to_vec();
            }
        };

        let body = match response.json::<ChatResponse>().await {
            Ok(b) => b,
            Err(e) => {
                warn!("LLM response parse failed (fail-open): {e}");
                return keyword_threats.to_vec();
            }
        };
        info!("Query:{}, Chat response {:?}", text, body);
        let content = match body.choices.first() {
            Some(c) => &c.message.content,
            None => {
                warn!("LLM returned no choices (fail-open)");
                return keyword_threats.to_vec();
            }
        };

        let llm_result: LlmResult = match serde_json::from_str(content) {
            Ok(r) => r,
            Err(e) => {
                warn!("LLM JSON parse failed (fail-open): {e} — raw: {content}");
                return keyword_threats.to_vec();
            }
        };

        debug!(
            "LLM verdict: threats={:?}, reasoning={:?}",
            llm_result.threats, llm_result.reasoning
        );

        // Convert string names back to ThreatKind.
        let verified: Vec<ThreatKind> = llm_result
            .threats
            .iter()
            .filter_map(|name| ThreatKind::from_variant_name(name))
            .collect();

        // If LLM returned something parseable, use it. Otherwise fail-open.
        if llm_result.threats.is_empty() && !keyword_threats.is_empty() {
            debug!("LLM says NOT an active alert — suppressing");
            return vec![];
        }

        if verified.is_empty() && !llm_result.threats.is_empty() {
            // LLM returned threat names we couldn't parse — fail-open.
            warn!(
                "LLM returned unparseable threats {:?} (fail-open)",
                llm_result.threats
            );
            return keyword_threats.to_vec();
        }

        verified
    }
}

impl std::fmt::Display for LlmFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LlmFilter(enabled={}, model={}, endpoint={}, timeout={}ms)",
            self.enabled,
            self.model,
            self.endpoint,
            self.timeout.as_millis(),
        )
    }
}
