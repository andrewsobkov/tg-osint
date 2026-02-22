#!/usr/bin/env bash
# Setup and run Ollama with the recommended model for tg_osint.
#
# Prerequisites:
#   Install Ollama: https://ollama.com/download
#   curl -fsSL https://ollama.com/install.sh | sh
#
# Usage:
#   ./run_llm_server.sh              # pull model + verify
#   ./run_llm_server.sh --3b         # use smaller 3B model (CPU / low RAM)

set -euo pipefail

MODEL="${LLM_MODEL:-gemma3:1b}"

if [[ "${1:-}" == "--3b" ]]; then
    MODEL="qwen2.5:3b"
    echo "Using 3B model (CPU-friendly)"
fi

# Check if ollama is installed
if ! command -v ollama &>/dev/null; then
    echo "ERROR: Ollama is not installed."
    echo "Install it:  curl -fsSL https://ollama.com/install.sh | sh"
    echo "Or visit:    https://ollama.com/download"
    exit 1
fi

# Check if the service is running
if ! curl -sf http://127.0.0.1:11434/ > /dev/null 2>&1; then
    echo "Ollama service is not running. Starting..."
    ollama serve &
    sleep 2
fi

# Pull model if not already available
echo "Pulling $MODEL (this only downloads once)..."
ollama pull "$MODEL"

# Verify
echo ""
echo "✅ Ready! Model '$MODEL' is available."
echo ""
echo "To enable in your bot, set in .env:"
echo "  LLM_ENABLED=true"
echo "  LLM_MODEL=$MODEL"
echo ""
echo "Test it:"
echo "  curl http://127.0.0.1:11434/v1/chat/completions \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"model\": \"$MODEL\", \"messages\": [{\"role\": \"user\", \"content\": \"Привіт!\"}]}'"


curl http://127.0.0.1:11434/v1/chat/completions -H 'Content-Type: application/json'  -d '{"model": "qwen2.5:7b", "messages": [{"role": "user", "content": "Привіт!"}]}'
