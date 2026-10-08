#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script constants
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/engine.sh"
REQUIRED_SERVICES=("oscmcpservice" "ccowmcpclient" "ccowmcpbridge" "oscwebserver" "oscreverseproxy" "oscapiservice" "cowstorage")
NO_CODE_UI_SERVICES=("oscwebserver" "oscreverseproxy" "oscapiservice" "cowstorage")
CERT_PATHS=("src/oscreverseproxy/certs" "${HOME}/continube/certs")
MCP_SESSION_DIR="${SCRIPT_DIR}/mcp-sessions/sessions"

# Setup mode: "full" (MCP + No-Code UI) or "nocode" (No-Code UI only)
SETUP_MODE="full"

# Docker command with sudo
DOCKER_CMD="sudo docker"
USE_SUDO=true

# Global variables for selected model
DETECTED_MODEL=""
DETECTED_MODEL_NAME=""


# Source environment variables
if [ -f "${SCRIPT_DIR}/etc/userconfig.env" ]; then
    set -a  # automatically export all variables
    source "${SCRIPT_DIR}/etc/userconfig.env"
    set +a  # disable auto-export
    echo -e "${GREEN}[INFO]${NC} Environment variables loaded from etc/userconfig.env"
else
    echo -e "${YELLOW}[WARNING]${NC} etc/userconfig.env not found, continuing without it"
fi

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║   Open Security Compliance MCP + No-Code UI Setup         ║"
    echo "║                   (WITH SUDO SUPPORT)                     ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Prompt user to select setup mode
select_setup_mode() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Choose your setup mode${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} MCP + No-Code UI  ${YELLOW}(Requires an LLM API key)${NC}"
    echo "     Enables AI-powered rule creation via MCP along with the"
    echo "     No-Code web interface."
    echo "     Services: oscmcpservice, ccowmcpclient, ccowmcpbridge,"
    echo "               oscwebserver, oscreverseproxy, oscapiservice, cowstorage"
    echo ""
    echo -e "  ${GREEN}2)${NC} No-Code UI Only   ${YELLOW}(No LLM API key needed)${NC}"
    echo "     Enables only the No-Code web interface for manual rule"
    echo "     creation and management. No AI/MCP features."
    echo "     Services: oscapiservice, oscreverseproxy, oscwebserver, cowstorage"
    echo ""

    while true; do
        read -p "Select setup mode [1/2]: " -r mode_choice
        case "$mode_choice" in
            1)
                SETUP_MODE="full"
                log_info "Selected: MCP + No-Code UI (full setup)"
                echo ""
                log_warning "You will need an API key for one of: Anthropic, OpenAI, Google Gemini or DeepSeek."
                echo ""
                break
                ;;
            2)
                SETUP_MODE="nocode"
                log_info "Selected: No-Code UI Only"
                echo ""
                break
                ;;
            *)
                log_error "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
}

# Helper function to update env variable in-place
update_env_variable() {
    local env_file=$1
    local var_name=$2
    local var_value=$3
    local comment=$4
    
    if [ ! -f "$env_file" ]; then
        mkdir -p "$(dirname "$env_file")"
        touch "$env_file"
    fi
    
    # Check if variable exists
    if grep -q "^${var_name}=" "$env_file"; then
        # Update existing variable in-place
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s|^${var_name}=.*|${var_name}=${var_value}|" "$env_file"
        else
            # Linux
            sed -i "s|^${var_name}=.*|${var_name}=${var_value}|" "$env_file"
        fi
    else
        # Add new variable with comment if it doesn't exist
        if [ -n "$comment" ]; then
            # Check if comment already exists
            if ! grep -q "^${comment}" "$env_file"; then
                echo "" >> "$env_file"
                echo "$comment" >> "$env_file"
            fi
        fi
        echo "${var_name}=${var_value}" >> "$env_file"
    fi
}

# Check if running with sufficient privileges
check_privileges() {
    log_info "Checking Docker access..."
    
    # First try without sudo
    if docker ps &> /dev/null; then
        log_success "Docker accessible without sudo"
        DOCKER_CMD="docker"
        USE_SUDO=false
    elif sudo docker ps &> /dev/null; then
        log_success "Docker accessible with sudo"
        DOCKER_CMD="sudo docker"
        USE_SUDO=true
        log_info "Running Docker commands with sudo"
    else
        log_error "Cannot access Docker even with sudo"
        exit 1
    fi
}

# Validate Docker installation
check_docker() {
    log_info "Checking Docker installation..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed!"
        echo ""
        echo "Please install Docker first:"
        echo "  - Linux: https://docs.docker.com/engine/install/"
        echo "  - Mac: https://docs.docker.com/desktop/install/mac-install/"
        echo "  - Windows: https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    fi
    
    if ! $DOCKER_CMD ps &> /dev/null; then
        log_error "Docker daemon is not running or you don't have permission to access it."
        echo ""
        echo "Please ensure:"
        echo "  1. Docker daemon is running: sudo systemctl start docker"
        echo "  2. Or add your user to docker group: sudo usermod -aG docker \$USER"
        echo "  3. Log out and back in for group changes to take effect"
        exit 1
    fi
    
    log_success "Docker is installed and running"
    $DOCKER_CMD --version
}

# Validate Docker Compose
check_docker_compose() {
    log_info "Checking Docker Compose installation..."
    
    if $DOCKER_CMD compose version &> /dev/null; then
        log_success "Docker Compose (plugin) is available"
        $DOCKER_CMD compose version
        if [ "$USE_SUDO" = true ]; then
            COMPOSE_CMD="sudo docker compose"
        else
            COMPOSE_CMD="docker compose"
        fi
    elif command -v docker-compose &> /dev/null; then
        log_success "Docker Compose (standalone) is available"
        docker-compose --version
        COMPOSE_CMD="docker-compose"
    else
        log_error "Docker Compose is not installed!"
        echo ""
        echo "Please install Docker Compose:"
        echo "  https://docs.docker.com/compose/install/"
        exit 1
    fi
}

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check available memory
    if command -v free &> /dev/null; then
        TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
        if [ "$TOTAL_MEM" -lt 16 ]; then
            log_warning "System has less than 16GB RAM. Open Security Compliance setup requires 16GB+ for optimal performance"
            echo ""
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_error "Setup cancelled. Please upgrade system resources."
                exit 1
            fi
        else
            log_success "System has ${TOTAL_MEM}GB RAM"
        fi
    fi
    
    # Check available disk space (cross-platform)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        AVAILABLE_SPACE=$(df -g "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
    else
        # Linux
        AVAILABLE_SPACE=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
    fi
    
    if [ -n "$AVAILABLE_SPACE" ] && [ "$AVAILABLE_SPACE" -lt 30 ]; then
        log_warning "Less than 30GB free disk space available. Recommended: 30GB+ for Open Security Compliance setup"
    elif [ -n "$AVAILABLE_SPACE" ]; then
        log_success "Sufficient disk space available (${AVAILABLE_SPACE}GB)"
    else
        log_warning "Could not determine available disk space"
    fi
    
    log_warning "Open Security Compliance setup requires a beefy machine or remote hosting:"
    echo "  - Recommended: 16GB+ RAM, 8+ CPU cores, 30GB+ disk"
    echo "  - 7 services will be running simultaneously"
}

# ---------------------------------------------------------------------------
# LLM provider and model selection
#
# The MCP client (goose) talks to one LLM provider. This step picks the provider,
# finds or asks for its API key, verifies the key against the provider's own API,
# lets the user choose from the models that key can actually use, and confirms
# the chosen model accepts tool calls — the rules assistant depends on them.
#
# Result, written to etc/userconfig.env as literal values:
#   GOOSE_PROVIDER, GOOSE_MODEL, the provider's key variable, MCP_MODEL
# ---------------------------------------------------------------------------

# id|label|goose provider|API key variable|where to get a key
LLM_PROVIDERS=(
    "anthropic|Anthropic (Claude)|anthropic|ANTHROPIC_API_KEY|https://console.anthropic.com/settings/keys"
    "openai|OpenAI (GPT)|openai|OPENAI_API_KEY|https://platform.openai.com/api-keys"
    "gemini|Google Gemini|google|GOOGLE_API_KEY|https://aistudio.google.com/apikey"
    "deepseek|DeepSeek|custom_deepseek|DEEPSEEK_API_KEY|https://platform.deepseek.com/api_keys"
)

LLM_PROVIDER=""
LLM_PROVIDER_LABEL=""
LLM_GOOSE_PROVIDER=""
LLM_KEY_VAR=""
LLM_KEY_URL=""
LLM_HTTP_CODE=""

select_llm_provider_entry() {
    local entry=$1
    IFS='|' read -r LLM_PROVIDER LLM_PROVIDER_LABEL LLM_GOOSE_PROVIDER LLM_KEY_VAR LLM_KEY_URL <<< "$entry"
}

# Auth headers for the selected provider, one per line. Fed to curl through a
# file descriptor so the key never appears in the process list.
llm_auth_headers() {
    local key=$1
    case "$LLM_PROVIDER" in
        anthropic) printf 'x-api-key: %s\nanthropic-version: 2023-06-01\n' "$key" ;;
        gemini)    printf 'x-goog-api-key: %s\n' "$key" ;;
        *)         printf 'Authorization: Bearer %s\n' "$key" ;;
    esac
    printf 'content-type: application/json\n'
}

# llm_request KEY URL OUTFILE [JSON_BODY] — sets LLM_HTTP_CODE ("000" on network failure)
llm_request() {
    local key=$1 url=$2 out=$3 body=${4:-}
    if [ -n "$body" ]; then
        LLM_HTTP_CODE=$(curl -sS -m 90 -w '%{http_code}' -o "$out" -X POST \
            -H @<(llm_auth_headers "$key") --data-binary "$body" "$url" 2>/dev/null) || LLM_HTTP_CODE="000"
    else
        LLM_HTTP_CODE=$(curl -sS -m 30 -w '%{http_code}' -o "$out" \
            -H @<(llm_auth_headers "$key") "$url" 2>/dev/null) || LLM_HTTP_CODE="000"
    fi
}

# The provider's own error message from a response body, if it has one.
llm_error_message() {
    python3 - "$1" <<'PY' 2>/dev/null || true
import json, sys
try:
    body = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)
err = body[0] if isinstance(body, list) and body else body
err = err.get("error", err) if isinstance(err, dict) else err
msg = err.get("message") if isinstance(err, dict) else err
if msg:
    print(str(msg)[:300])
PY
}

explain_llm_http_failure() {
    local code=$1 body_file=$2
    case "$code" in
        401|403) echo "  - The API key was rejected (HTTP $code): invalid, expired, or without access" ;;
        400)     echo "  - The provider rejected the request (HTTP 400)" ;;
        402)     echo "  - The account has no credit or balance left (HTTP 402); top it up with the provider" ;;
        429)     echo "  - Rate limit or quota exceeded (HTTP 429), or the account has no credit" ;;
        000)     echo "  - Could not reach the provider: check network access and proxies" ;;
        *)       echo "  - Unexpected response from the provider (HTTP $code)" ;;
    esac
    local detail
    detail=$(llm_error_message "$body_file")
    if [ -n "$detail" ]; then
        echo "  - Provider says: $detail"
    fi
}

# Fetch the models the key can use. Writes "id<TAB>display" lines to $2, best
# default first. Returns 1 if the key is rejected or nothing usable comes back.
llm_fetch_models() {
    local key=$1 out=$2
    local raw page next_token="" pages=0
    raw=$(mktemp)
    echo "[]" > "$raw"

    while [ $pages -lt 20 ]; do
        pages=$((pages + 1))
        page=$(mktemp)
        local url
        case "$LLM_PROVIDER" in
            anthropic) url="https://api.anthropic.com/v1/models?limit=100${next_token:+&after_id=$next_token}" ;;
            openai)    url="https://api.openai.com/v1/models" ;;
            gemini)    url="https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000${next_token:+&pageToken=$next_token}" ;;
            deepseek)  url="https://api.deepseek.com/models" ;;
        esac
        llm_request "$key" "$url" "$page"
        if [ "$LLM_HTTP_CODE" != "200" ]; then
            log_error "$LLM_PROVIDER_LABEL API key verification failed"
            explain_llm_http_failure "$LLM_HTTP_CODE" "$page"
            rm -f "$page" "$raw"
            return 1
        fi
        # Append this page's models; print the token for the next page, if any.
        next_token=$(python3 - "$LLM_PROVIDER" "$page" "$raw" <<'PY'
import json, sys
provider, page_path, raw_path = sys.argv[1:4]
page = json.load(open(page_path, encoding="utf-8"))
acc = json.load(open(raw_path, encoding="utf-8"))
if provider == "gemini":
    acc.extend(page.get("models") or [])
    nxt = page.get("nextPageToken") or ""
else:
    acc.extend(page.get("data") or [])
    nxt = (page.get("last_id") or "") if provider == "anthropic" and page.get("has_more") else ""
json.dump(acc, open(raw_path, "w", encoding="utf-8"))
print(nxt)
PY
) || { log_error "Could not read the model list from $LLM_PROVIDER_LABEL"; rm -f "$page" "$raw"; return 1; }
        rm -f "$page"
        [ -z "$next_token" ] && break
    done

    python3 - "$LLM_PROVIDER" "$raw" > "$out" <<'PY'
import json, re, sys
provider, raw_path = sys.argv[1:3]
models = json.load(open(raw_path, encoding="utf-8"))

# One ranking for every provider: newest version first, then the flagship tier
# before smaller ones, then stable before preview. The recommended model is the
# newest flagship, so the default does not drift to a small or dated model.
def version(model_id):
    m = re.search(r"(\d+(?:\.\d+)?)", model_id)
    return float(m.group(1)) if m else -1.0

rows = {}
for m in models:
    if provider == "anthropic":
        mid, display, created = m.get("id") or "", m.get("display_name"), m.get("created_at") or ""
        if not mid.startswith("claude"):
            continue
        tier = 0 if "sonnet" in mid else 1 if "opus" in mid else 2
        flagship = "sonnet" in mid
    elif provider == "openai":
        mid, created = m.get("id") or "", str(m.get("created") or 0).zfill(12)
        display = mid
        # Chat models only: the list also has embedding, audio, image and moderation models.
        if not re.match(r"^(gpt-|o\d|chatgpt-)", mid) or re.search(
                r"embedding|tts|whisper|transcribe|dall-e|image|audio|realtime|moderation|search|instruct|babbage|davinci|codex|computer-use|deep-research", mid):
            continue
        tier = 2 if "nano" in mid else 1 if re.search(r"mini|luna|-pro\b", mid) else 0
        flagship = tier == 0 and mid.startswith("gpt-")
    elif provider == "gemini":
        name = m.get("name") or ""
        mid, display, created = name[len("models/"):], m.get("displayName"), ""
        if not name.startswith("models/gemini") or "generateContent" not in (m.get("supportedGenerationMethods") or []):
            continue
        # Speech, image, transcription, robotics and similar specialised models.
        if re.search(r"embedding|image|tts|live|audio|aqa|vision|transcribe|robotics|computer-use|customtools|nano-banana|omni", mid):
            continue
        tier = 2 if "flash-lite" in mid else 1 if "flash" in mid else 0 if "pro" in mid else 3
        flagship = tier == 0 and version(mid) > 0
    else:  # deepseek
        mid = m.get("id") or ""
        display, created = mid, ""
        tier = 1 if "reasoner" in mid else 0
        flagship = tier == 0
    if not mid:
        continue
    preview = 1 if re.search(r"preview|exp|latest", mid) else 0
    rows[mid] = (-version(mid), tier, preview, created, mid, display or mid, flagship)

# Newest version, then tier, then stable before preview, then most recently created.
ordered = sorted(rows.values(), key=lambda r: r[3], reverse=True)
ordered = sorted(ordered, key=lambda r: (r[0], r[1], r[2]))
best = next((r for r in ordered if r[6]), None)
if best:
    ordered.remove(best)
    ordered.insert(0, best)
for r in ordered:
    print(f"{r[4]}\t{r[5]}")
PY
    rm -f "$raw"
    if [ ! -s "$out" ]; then
        log_error "$LLM_PROVIDER_LABEL returned no chat models usable with this key"
        return 1
    fi
    return 0
}

# One small request with a tool attached. Proves the key can use this model and
# that the model accepts tool definitions; the rules assistant cannot work without.
llm_test_model() {
    local key=$1 model=$2
    local out url body
    out=$(mktemp)
    case "$LLM_PROVIDER" in
        anthropic)
            url="https://api.anthropic.com/v1/messages"
            body="{\"model\":\"$model\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK.\"}],\"tools\":[{\"name\":\"ping\",\"description\":\"Health check\",\"input_schema\":{\"type\":\"object\",\"properties\":{}}}]}" ;;
        openai)
            # Test the endpoint goose will use: it sends GPT-5, GPT-6 and o-series
            # models to the Responses API (is_openai_responses_model in goose), and
            # some of them refuse function tools on Chat Completions.
            local lower_model
            lower_model=$(printf '%s' "$model" | tr '[:upper:]' '[:lower:]')
            if [[ "$lower_model" =~ (^|[-/])(o[0-9]+($|-)|gpt-(5|6)($|[-.])) ]]; then
                url="https://api.openai.com/v1/responses"
                body="{\"model\":\"$model\",\"max_output_tokens\":256,\"input\":\"Reply with OK.\",\"tools\":[{\"type\":\"function\",\"name\":\"ping\",\"description\":\"Health check\",\"parameters\":{\"type\":\"object\",\"properties\":{}}}]}"
            else
                url="https://api.openai.com/v1/chat/completions"
                body="{\"model\":\"$model\",\"max_completion_tokens\":256,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK.\"}],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"ping\",\"description\":\"Health check\",\"parameters\":{\"type\":\"object\",\"properties\":{}}}}]}"
            fi ;;
        gemini)
            url="https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent"
            body="{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"Reply with OK.\"}]}],\"tools\":[{\"functionDeclarations\":[{\"name\":\"ping\",\"description\":\"Health check\"}]}],\"generationConfig\":{\"maxOutputTokens\":256}}" ;;
        deepseek)
            url="https://api.deepseek.com/chat/completions"
            body="{\"model\":\"$model\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK.\"}],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"ping\",\"description\":\"Health check\",\"parameters\":{\"type\":\"object\",\"properties\":{}}}}]}" ;;
    esac
    log_info "Testing $model with a tool-enabled request..."
    llm_request "$key" "$url" "$out" "$body"
    if [ "$LLM_HTTP_CODE" = "200" ]; then
        rm -f "$out"
        log_success "$model works with this key and accepts tool calls"
        return 0
    fi
    log_error "$model failed the test request"
    explain_llm_http_failure "$LLM_HTTP_CODE" "$out"
    rm -f "$out"
    return 1
}

remove_env_variable() {
    local env_file=$1 var_name=$2
    [ -f "$env_file" ] || return 0
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "/^${var_name}=/d" "$env_file"
    else
        sed -i "/^${var_name}=/d" "$env_file"
    fi
}

check_llm_provider() {
    ENV_FILE="${SCRIPT_DIR}/etc/userconfig.env"

    if ! command -v python3 &> /dev/null; then
        log_error "python3 is required to read the providers' model lists"
        echo "  - Install Python 3 and re-run setup"
        exit 1
    fi
    if ! command -v curl &> /dev/null; then
        log_error "curl is required to verify the API key"
        exit 1
    fi

    local current_provider="${GOOSE_PROVIDER:-}"
    local default_choice=1 i=1 entry
    echo ""
    echo -e "${CYAN}Choose the LLM provider for the MCP assistant${NC}"
    for entry in "${LLM_PROVIDERS[@]}"; do
        select_llm_provider_entry "$entry"
        local marker=""
        if [ "$LLM_GOOSE_PROVIDER" = "$current_provider" ]; then
            marker=" (current)"
            default_choice=$i
        fi
        echo "  $i) $LLM_PROVIDER_LABEL$marker"
        i=$((i + 1))
    done

    while true; do
        local choice
        read -p "Select provider [1-${#LLM_PROVIDERS[@]}] (default: $default_choice): " -r choice
        choice=${choice:-$default_choice}
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#LLM_PROVIDERS[@]} ]; then
            break
        fi
        log_warning "Enter a number between 1 and ${#LLM_PROVIDERS[@]}."
    done
    select_llm_provider_entry "${LLM_PROVIDERS[$((choice - 1))]}"
    log_info "Selected provider: $LLM_PROVIDER_LABEL"

    # Use the key already in etc/userconfig.env (or the environment) when there is one.
    local api_key="${!LLM_KEY_VAR:-}"
    local key_from_file=false
    [ -n "$api_key" ] && key_from_file=true

    # Whole-line reads for yes/no: a single-keypress read leaves the Enter typed
    # after "Y" in the buffer, where the next prompt takes it as an empty answer.
    ask_retry_key() {
        local reply
        read -r -p "Try another API key? (Y/n): " reply
        if [[ "$reply" =~ ^[Nn] ]]; then
            log_error "Setup cancelled: a working $LLM_PROVIDER_LABEL API key is required"
            rm -f "$models_file"
            exit 1
        fi
    }

    local models_file
    models_file=$(mktemp)
    while true; do
        if [ -z "$api_key" ]; then
            echo ""
            echo "An API key for $LLM_PROVIDER_LABEL is required."
            echo "Get one from: $LLM_KEY_URL"
            read -r -s -p "Enter your $LLM_PROVIDER_LABEL API key (input hidden): " api_key
            echo ""
            if [ -z "$api_key" ]; then
                log_warning "No API key entered"
                ask_retry_key
                continue
            fi
        elif $key_from_file; then
            log_info "Using $LLM_KEY_VAR from etc/userconfig.env"
        fi

        log_info "Verifying the $LLM_PROVIDER_LABEL API key..."
        if llm_fetch_models "$api_key" "$models_file"; then
            log_success "$LLM_PROVIDER_LABEL API key is valid"
            break
        fi

        if $key_from_file; then
            remove_env_variable "$ENV_FILE" "$LLM_KEY_VAR"
            log_info "Removed the rejected $LLM_KEY_VAR from etc/userconfig.env"
            key_from_file=false
        fi
        api_key=""
        ask_retry_key
    done

    local model_ids=() model_names=()
    local model_id model_name
    while IFS=$'\t' read -r model_id model_name; do
        [ -z "$model_id" ] && continue
        model_ids+=("$model_id")
        model_names+=("$model_name")
    done < "$models_file"
    rm -f "$models_file"

    echo ""
    echo "Models available with this key:"
    local idx
    for idx in "${!model_ids[@]}"; do
        local label="${model_names[$idx]}"
        [ "$label" = "${model_ids[$idx]}" ] && label="" || label=" — $label"
        echo "  $((idx + 1))) ${model_ids[$idx]}$label$([ "$idx" -eq 0 ] && echo "  (recommended)")"
    done

    while true; do
        local selection
        read -p "Select model [1-${#model_ids[@]}] (default: 1): " -r selection
        selection=${selection:-1}
        if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#model_ids[@]} ]; then
            log_warning "Enter a number between 1 and ${#model_ids[@]}."
            continue
        fi
        DETECTED_MODEL="${model_ids[$((selection - 1))]}"
        DETECTED_MODEL_NAME="${model_names[$((selection - 1))]}"
        if llm_test_model "$api_key" "$DETECTED_MODEL"; then
            break
        fi
        log_warning "Choose a different model."
    done

    update_env_variable "$ENV_FILE" "GOOSE_PROVIDER" "$LLM_GOOSE_PROVIDER" "# LLM provider for the MCP assistant (goose): anthropic, openai, google or custom_deepseek"
    update_env_variable "$ENV_FILE" "GOOSE_MODEL" "$DETECTED_MODEL" "# LLM model for the MCP assistant (goose)"
    update_env_variable "$ENV_FILE" "$LLM_KEY_VAR" "$api_key" "# API key for $LLM_PROVIDER_LABEL"
    update_env_variable "$ENV_FILE" "MCP_MODEL" "$DETECTED_MODEL" "# Selected model (goose reads GOOSE_MODEL; kept for compatibility)"
    if [ "$LLM_PROVIDER" = "deepseek" ]; then
        # Same as the ComplianceCow deployment: DeepSeek runs with thinking off.
        update_env_variable "$ENV_FILE" "GOOSE_THINKING_DISABLE_MODELS" "$DETECTED_MODEL" "# DeepSeek models that run with thinking disabled"
    fi

    export GOOSE_PROVIDER="$LLM_GOOSE_PROVIDER" GOOSE_MODEL="$DETECTED_MODEL" MCP_MODEL="$DETECTED_MODEL"
    log_success "Saved to etc/userconfig.env: GOOSE_PROVIDER=$LLM_GOOSE_PROVIDER, GOOSE_MODEL=$DETECTED_MODEL, $LLM_KEY_VAR"
}

# goose refuses to start without GOOSE_SERVER__SECRET_KEY, and the bridge must
# send the same value. An existing secret is kept so the two stay paired across
# re-runs; the insecure built-in default "mysecret" is replaced.
ensure_goose_server_secret() {
    ENV_FILE="${SCRIPT_DIR}/etc/userconfig.env"
    local secret="${GOOSE_SERVER__SECRET_KEY:-${GOOSE_SERVER_SECRET_KEY:-}}"
    if [ -z "$secret" ] || [ "$secret" = "mysecret" ]; then
        secret=$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')
        log_info "Generated the shared secret for the MCP client and bridge"
    fi
    update_env_variable "$ENV_FILE" "GOOSE_SERVER__SECRET_KEY" "$secret" "# Shared secret between the MCP bridge and the MCP client (goose); both must match"
    update_env_variable "$ENV_FILE" "GOOSE_SERVER_SECRET_KEY" "$secret" ""
}

# Validate MinIO credentials
check_minio_credentials() {
    log_info "Checking MinIO credentials..."
    
    ENV_FILE="${SCRIPT_DIR}/etc/policycow.env"
    
    # Load environment variables if file exists
    if [ -f "$ENV_FILE" ]; then
        set -a
        source "$ENV_FILE"
        set +a
    fi
    
    # Check if credentials are set
    MINIO_USER_MISSING=false
    MINIO_PASS_MISSING=false
    
    if [ -z "$MINIO_ROOT_USER" ]; then
        MINIO_USER_MISSING=true
    fi
    
    if [ -z "$MINIO_ROOT_PASSWORD" ]; then
        MINIO_PASS_MISSING=true
    fi
    
    # Validation loop
    while true; do
        # Prompt for username if missing
        if [ "$MINIO_USER_MISSING" = true ] || [ -z "$MINIO_ROOT_USER" ]; then
            log_warning "MinIO root username not found in environment"
            echo ""
            echo "MinIO requires a root username for authentication."
            echo "Requirements: Minimum 3 characters"
            echo ""
            read -p "Enter MinIO root username: " -r MINIO_ROOT_USER
            echo ""
        fi
        
        # Validate username
        if [ ${#MINIO_ROOT_USER} -lt 3 ]; then
            log_error "MinIO username must be at least 3 characters long"
            MINIO_ROOT_USER=""
            continue
        fi
        
        # Check for invalid characters in username (spaces, special chars that could cause issues)
        if [[ "$MINIO_ROOT_USER" =~ [[:space:]] ]]; then
            log_error "MinIO username cannot contain spaces"
            MINIO_ROOT_USER=""
            continue
        fi
        
        # Prompt for password if missing
        if [ "$MINIO_PASS_MISSING" = true ] || [ -z "$MINIO_ROOT_PASSWORD" ]; then
            log_warning "MinIO root password not found in environment"
            echo ""
            echo "MinIO requires a root password for authentication."
            echo "Requirements: Minimum 8 characters"
            echo ""
            read -s -p "Enter MinIO root password: " MINIO_ROOT_PASSWORD
            echo ""
            read -s -p "Confirm MinIO root password: " MINIO_ROOT_PASSWORD_CONFIRM
            echo ""
            echo ""
            
            if [ "$MINIO_ROOT_PASSWORD" != "$MINIO_ROOT_PASSWORD_CONFIRM" ]; then
                log_error "Passwords do not match"
                MINIO_ROOT_PASSWORD=""
                MINIO_ROOT_PASSWORD_CONFIRM=""
                continue
            fi
        fi
        
        # Validate password length
        if [ ${#MINIO_ROOT_PASSWORD} -lt 8 ]; then
            log_error "MinIO password must be at least 8 characters long"
            MINIO_ROOT_PASSWORD=""
            MINIO_ROOT_PASSWORD_CONFIRM=""
            MINIO_PASS_MISSING=true
            continue
        fi
        
        # Check for spaces in password
        if [[ "$MINIO_ROOT_PASSWORD" =~ [[:space:]] ]]; then
            log_error "MinIO password cannot contain spaces"
            MINIO_ROOT_PASSWORD=""
            MINIO_ROOT_PASSWORD_CONFIRM=""
            MINIO_PASS_MISSING=true
            continue
        fi
        
        # All validations passed
        log_success "MinIO credentials validated successfully"
        log_info "Username: $MINIO_ROOT_USER (${#MINIO_ROOT_USER} characters)"
        log_info "Password: ******** (${#MINIO_ROOT_PASSWORD} characters)"
        
        # Save credentials to env file
        if [ ! -f "$ENV_FILE" ]; then
            log_info "Creating etc/policycow.env file..."
            mkdir -p "$(dirname "$ENV_FILE")"
            touch "$ENV_FILE"
        fi
        
        # Update credentials in-place
        update_env_variable "$ENV_FILE" "MINIO_ROOT_USER" "$MINIO_ROOT_USER" "# MinIO Root Credentials"
        update_env_variable "$ENV_FILE" "MINIO_ROOT_PASSWORD" "$MINIO_ROOT_PASSWORD" ""
        
        log_success "MinIO credentials saved to etc/policycow.env"
        
        # Export for current session
        export MINIO_ROOT_USER
        export MINIO_ROOT_PASSWORD
        
        break
    done
}

# Validate SSL certificates
check_ssl_certificates() {
    log_info "Checking SSL certificates..."
    
    CERT_FOUND=false
    CERT_LOCATION=""
    
    for cert_path in "${CERT_PATHS[@]}"; do
        if [ -f "$cert_path/fullchain.pem" ] && [ -f "$cert_path/privkey.pem" ]; then
            CERT_FOUND=true
            CERT_LOCATION="$cert_path"
            break
        fi
    done
    
    if [ "$CERT_FOUND" = true ]; then
        log_success "SSL certificates found at: $CERT_LOCATION"
        
        # Validate certificate expiration
        if command -v openssl &> /dev/null; then
            EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT_LOCATION/fullchain.pem" | cut -d= -f2)
            log_info "Certificate expires on: $EXPIRY_DATE"
        fi
    else
        log_warning "SSL certificates not found!"
        echo ""
        echo "Please place your SSL certificates in one of these locations:"
        echo "  1. ${SCRIPT_DIR}/src/oscreverseproxy/certs/"
        echo "  2. ${HOME}/continube/certs/"
        echo ""
        echo "Required files:"
        echo "  - fullchain.pem"
        echo "  - privkey.pem"
        echo ""
        read -p "Do you want to continue without SSL certificates? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Setup cancelled. Please add SSL certificates and try again."
            exit 1
        fi
    fi
}

# Validate environment files
check_env_files() {
    log_info "Checking environment configuration files..."
    
    REQUIRED_ENV_FILES=("etc/userconfig.env" "etc/policycow.env")
    MISSING_FILES=()
    
    for env_file in "${REQUIRED_ENV_FILES[@]}"; do
        if [ ! -f "$env_file" ]; then
            MISSING_FILES+=("$env_file")
        fi
    done
    
    if [ ${#MISSING_FILES[@]} -gt 0 ]; then
        log_error "Missing environment files:"
        for file in "${MISSING_FILES[@]}"; do
            echo "  - $file"
        done
        exit 1
    fi
    
    log_success "All required environment files found"
    
    # Run export_env.sh if it exists
    if [ -f "export_env.sh" ]; then
        log_info "Running export_env.sh..."
        if bash export_env.sh; then
            log_success "Environment variables exported successfully"
        else
            log_warning "export_env.sh execution had warnings, continuing..."
        fi
    else
        log_warning "export_env.sh not found, skipping environment export"
    fi
}

# Clean up dangling containers and images
cleanup_docker() {
    log_info "Cleaning up dangling Docker resources..."
    
    # Stop existing containers for these services
    for service in "${REQUIRED_SERVICES[@]}"; do
        if $DOCKER_CMD ps -a --format '{{.Names}}' | grep -q "^${service}$"; then
            log_info "Stopping existing container: $service"
            $DOCKER_CMD stop "$service" 2>/dev/null || true
            $DOCKER_CMD rm "$service" 2>/dev/null || true
        fi
    done
    
    # Remove dangling images
    DANGLING_IMAGES=$($DOCKER_CMD images -f "dangling=true" -q)
    if [ -n "$DANGLING_IMAGES" ]; then
        log_info "Removing dangling images..."
        $DOCKER_CMD rmi $DANGLING_IMAGES 2>/dev/null || true
    fi
    
    # Clean up unused networks (except Open Security Compliance networks)
    log_info "Pruning unused networks..."
    $DOCKER_CMD network prune -f 2>/dev/null || true
    
    log_success "Docker cleanup completed"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p "${HOME}/tmp/cowctl/minio" && chown -R "$(id -un)":"$(id -gn 2>/dev/null)" "${HOME}/tmp/cowctl/minio"
    mkdir -p exported-data && chown -R "$(id -un)":"$(id -gn 2>/dev/null)" exported-data
    mkdir -p catalog/localcatalog && chown -R "$(id -un)":"$(id -gn 2>/dev/null)" catalog/localcatalog
    mkdir -p mcp-config && chown -R "$(id -un)":"$(id -gn 2>/dev/null)" mcp-config
    mkdir -p "$MCP_SESSION_DIR" && chown -R "$(id -un)":"$(id -gn 2>/dev/null)" "$MCP_SESSION_DIR"

    # Every other host folder the compose file bind-mounts. Docker creates missing ones itself
    # (as root); Podman refuses to start the container, so create them as the current user.
    local dir
    for dir in catalog/localcatalog/rules catalog/applicationscope catalog/designnotes \
               catalog/globalcatalog/dashboards catalog/globalcatalog/methods catalog/globalcatalog/rulegroups \
               cowexecutions mcp-server mcp-sessions mcp-state; do
        mkdir -p "$dir" && chown -R "$(id -un)":"$(id -gn 2>/dev/null)" "$dir"
    done
    
    log_success "Directories created"
    log_info "MCP sessions will persist in: $MCP_SESSION_DIR"
}

# Build and start services
build_services() {
    log_info "Building Docker images (this may take several minutes)..."
    
    if $COMPOSE_CMD -f docker-compose-osc.yaml build oscwebserver oscreverseproxy oscapiservice cowstorage ccowmcpclient ccowmcpbridge oscmcpservice; then
        log_success "Docker images built successfully"
    else
        log_error "Failed to build Docker images"
        exit 1
    fi
}

# Health check function for MCP service
wait_for_mcp_health() {
    local max_attempts=60
    local attempt=0
    local mcp_port="${OSC_MCP_PORT:-45678}"
    local mcp_health_endpoint="http://localhost:${mcp_port}/health"
    
    log_info "Waiting for MCP service to be ready..."
    log_info "Health check endpoint: ${mcp_health_endpoint}"
    
    while [ $attempt -lt $max_attempts ]; do
        # Check if container is running first
        if ! $DOCKER_CMD ps --filter "name=oscmcpservice" --filter "status=running" | grep -q oscmcpservice; then
            log_warning "MCP service container not running yet (attempt $((attempt + 1))/$max_attempts)"
            attempt=$((attempt + 1))
            sleep 2
            continue
        fi
        
        # Try to hit the health endpoint
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "${mcp_health_endpoint}" 2>/dev/null || echo "000")
        
        if [ "$http_code" = "200" ] || [ "$http_code" = "404" ]; then
            if [ "$http_code" = "200" ]; then
                log_success "MCP service is healthy and responding (HTTP 200)"
            else
                log_success "MCP service is up and responding (HTTP 404 - server is running)"
            fi
            return 0
        elif [ "$http_code" = "000" ]; then
            echo -ne "\r${BLUE}[INFO]${NC} Waiting for MCP service... (attempt $((attempt + 1))/$max_attempts) - Connection refused"
        else
            echo -ne "\r${BLUE}[INFO]${NC} Waiting for MCP service... (attempt $((attempt + 1))/$max_attempts) - HTTP $http_code"
        fi
        
        attempt=$((attempt + 1))
        sleep 2
    done
    
    echo ""
    log_error "MCP service health check timed out after $((max_attempts * 2)) seconds"
    log_info "Checking MCP service logs..."
    $COMPOSE_CMD -f docker-compose-osc.yaml logs --tail=20 oscmcpservice
    return 1
}

start_services() {
    log_info "Starting all services..."
    
    # Start storage first
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d cowstorage; then
        log_success "Storage service started"
        sleep 5
    else
        log_error "Failed to start storage service"
        exit 1
    fi
    
    # Start MCP service first (before ccowmcpclient)
    log_info "Starting MCP service..."
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d oscmcpservice; then
        log_success "MCP service container started"
    else
        log_error "Failed to start MCP service"
        exit 1
    fi
    
    # Wait for MCP service to be healthy
    if ! wait_for_mcp_health; then
        log_error "MCP service failed to become healthy"
        echo ""
        read -p "Continue with remaining services anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Setup cancelled. Please check MCP service configuration."
            exit 1
        fi
        log_warning "Continuing despite MCP service issues..."
    fi
    
    # Now start remaining services including ccowmcpclient
    log_info "Starting remaining services..."
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d oscapiservice oscwebserver oscreverseproxy ccowmcpclient ccowmcpbridge; then
        log_success "All services started successfully"
    else
        log_error "Failed to start services"
        exit 1
    fi
}

# Wait for services to be healthy
wait_for_services() {
    log_info "Waiting for services to be ready (this may take a minute)..."
    
    local max_attempts=60
    local attempt=0
    local services_ready=0
    
    while [ $attempt -lt $max_attempts ] && [ $services_ready -lt 3 ]; do
        services_ready=0
        
        if $DOCKER_CMD ps --filter "name=oscapiservice" --filter "status=running" | grep -q oscapiservice; then
            services_ready=$((services_ready + 1))
        fi
        
        if $DOCKER_CMD ps --filter "name=ccowmcpclient" --filter "status=running" | grep -q ccowmcpclient; then
            services_ready=$((services_ready + 1))
        fi

        if $DOCKER_CMD ps --filter "name=ccowmcpbridge" --filter "status=running" | grep -q ccowmcpbridge; then
            services_ready=$((services_ready + 1))
        fi
        
        if $DOCKER_CMD ps --filter "name=oscmcpservice" --filter "status=running" | grep -q oscmcpservice; then
            services_ready=$((services_ready + 1))
        fi
        
        if [ $services_ready -ge 3 ]; then
            log_success "Core services are running"
            return 0
        fi
        
        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done
    
    log_warning "Some services may still be starting up. Check status with: $DOCKER_CMD ps"
}

# Display service status
show_service_status() {
    echo ""
    log_info "Service Status:"
    echo ""
    $DOCKER_CMD ps --filter "name=cow" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
}

# Display MCP-specific information
show_mcp_info() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      Open Security Compliance Setup Completed!            ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_info "Access URLs:"
    echo "  - Web UI (HTTPS): https://localhost:${OSC_HTTPS_PORT:-443}"
    echo "  - Web UI (HTTP): http://localhost:3001"
    echo "  - API Service: http://localhost:9080"
    echo "  - MinIO Console: http://localhost:9001"
    echo "  - MCP Bridge: http://localhost:8095"
    echo "  - MCP Service: http://localhost:${OSC_MCP_PORT:-45678}"
    echo "  - MCP Health Check: http://localhost:${OSC_MCP_PORT:-45678}/health"
    echo ""
    log_info "AI Model Configuration:"
    echo "  - Provider: ${LLM_PROVIDER_LABEL:-${GOOSE_PROVIDER:-not configured}}"
    echo "  - Model: ${DETECTED_MODEL:-${GOOSE_MODEL:-not configured}}"
    echo "  - MCP Sessions: $MCP_SESSION_DIR"
    echo "  - API Key: Configured (from environment)"
    echo ""
    log_info "Rule Creation Methods:"
    echo "  1. Manual UI: Web UI → Reverse Proxy → API Service"
    echo "  2. MCP UI Mode: Web UI → Reverse Proxy → MCP Bridge → MCP Client → MCP Service"
    echo "  3. External MCP: Goose/Claude → MCP (port ${OSC_MCP_PORT:-45678})"
    echo ""
    log_info "Useful Commands:"
    echo "  - View all logs: $COMPOSE_CMD -f docker-compose-osc.yaml logs -f"
    echo "  - View MCP Client logs: $COMPOSE_CMD -f docker-compose-osc.yaml logs -f ccowmcpclient"
    echo "  - View MCP Bridge logs: $COMPOSE_CMD -f docker-compose-osc.yaml logs -f ccowmcpbridge"
    echo "  - View MCP logs: $COMPOSE_CMD -f docker-compose-osc.yaml logs -f oscmcpservice"
    echo "  - Check MCP health: curl http://localhost:${OSC_MCP_PORT:-45678}/health"
    echo "  - Stop services: sh down.sh osc"
    echo "  - Restart services: $COMPOSE_CMD -f docker-compose-osc.yaml restart"
    if [ "$COW_ENGINE" = "podman" ]; then
        echo "  (Podman: run 'export COW_ENGINE=podman' first in a new shell)"
    fi
    echo "  - Check status: $DOCKER_CMD ps"
    echo ""
    log_warning "Important Notes:"
    echo "  ⚠️  Change the LLM provider or model later with: ./setup.sh --configure-llm"
    echo "  ⚠️  MCP sessions persist across restarts"
    echo "  ⚠️  This setup does NOT support multi-tenancy"
    echo "  ⚠️  Not tested at scale - for development/testing only"
    echo "  ⚠️  Ensure you have a beefy machine (16GB+ RAM, 8+ cores)"
    echo ""
}

# Build services for No-Code UI only mode
build_services_nocode() {
    log_info "Building Docker images for No-Code UI services (this may take several minutes)..."

    if $COMPOSE_CMD -f docker-compose-osc.yaml build oscwebserver oscreverseproxy oscapiservice cowstorage; then
        log_success "Docker images built successfully"
    else
        log_error "Failed to build Docker images"
        exit 1
    fi
}

# Start services for No-Code UI only mode
start_services_nocode() {
    log_info "Starting No-Code UI services..."

    # Start storage first
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d cowstorage; then
        log_success "Storage service started"
        sleep 5
    else
        log_error "Failed to start storage service"
        exit 1
    fi

    # Start remaining No-Code UI services
    log_info "Starting remaining services..."
    if $COMPOSE_CMD -f docker-compose-osc.yaml up -d oscapiservice oscwebserver oscreverseproxy; then
        log_success "All No-Code UI services started successfully"
    else
        log_error "Failed to start services"
        exit 1
    fi
}

# Wait for No-Code UI services to be healthy
wait_for_services_nocode() {
    log_info "Waiting for services to be ready (this may take a minute)..."

    local max_attempts=60
    local attempt=0
    local services_ready=0

    while [ $attempt -lt $max_attempts ] && [ $services_ready -lt 3 ]; do
        services_ready=0

        if $DOCKER_CMD ps --filter "name=oscapiservice" --filter "status=running" | grep -q oscapiservice; then
            services_ready=$((services_ready + 1))
        fi

        if $DOCKER_CMD ps --filter "name=oscwebserver" --filter "status=running" | grep -q oscwebserver; then
            services_ready=$((services_ready + 1))
        fi

        if $DOCKER_CMD ps --filter "name=oscreverseproxy" --filter "status=running" | grep -q oscreverseproxy; then
            services_ready=$((services_ready + 1))
        fi

        if [ $services_ready -ge 3 ]; then
            log_success "Core services are running"
            return 0
        fi

        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done

    log_warning "Some services may still be starting up. Check status with: $DOCKER_CMD ps"
}

# Clean up dangling containers for No-Code UI only mode
cleanup_docker_nocode() {
    log_info "Cleaning up dangling Docker resources..."

    for service in "${NO_CODE_UI_SERVICES[@]}"; do
        if $DOCKER_CMD ps -a --format '{{.Names}}' | grep -q "^${service}$"; then
            log_info "Stopping existing container: $service"
            $DOCKER_CMD stop "$service" 2>/dev/null || true
            $DOCKER_CMD rm "$service" 2>/dev/null || true
        fi
    done

    # Remove dangling images
    DANGLING_IMAGES=$($DOCKER_CMD images -f "dangling=true" -q)
    if [ -n "$DANGLING_IMAGES" ]; then
        log_info "Removing dangling images..."
        $DOCKER_CMD rmi $DANGLING_IMAGES 2>/dev/null || true
    fi

    log_info "Pruning unused networks..."
    $DOCKER_CMD network prune -f 2>/dev/null || true

    log_success "Docker cleanup completed"
}

# Display completion info for No-Code UI only mode
show_nocode_info() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    Open Security Compliance No-Code UI Setup Completed!  ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_info "Access URLs:"
    echo "  - Web UI (HTTPS): https://localhost:${OSC_HTTPS_PORT:-443}"
    echo "  - Web UI (HTTP): http://localhost:3001"
    echo "  - API Service: http://localhost:9080"
    echo "  - MinIO Console: http://localhost:9001"
    echo ""
    log_info "Useful Commands:"
    echo "  - View all logs: $COMPOSE_CMD -f docker-compose-osc.yaml logs -f"
    echo "  - Stop services: sh down.sh osc"
    echo "  - Restart services: $COMPOSE_CMD -f docker-compose-osc.yaml restart"
    if [ "$COW_ENGINE" = "podman" ]; then
        echo "  (Podman: run 'export COW_ENGINE=podman' first in a new shell)"
    fi
    echo "  - Check status: $DOCKER_CMD ps"
    echo ""
    log_warning "Important Notes:"
    echo "  - MCP/AI features are not enabled in this mode"
    echo "  - To enable MCP features, re-run setup and select option 1 with an LLM API key"
    echo "  - This setup does NOT support multi-tenancy"
    echo "  - Not tested at scale - for development/testing only"
    echo ""
}

# Main execution
main() {
    # Change only the LLM provider/model of an existing installation.
    if [ "${1:-}" = "--configure-llm" ]; then
        print_banner
        check_llm_provider
        ensure_goose_server_secret
        echo ""
        log_success "LLM configuration saved to etc/userconfig.env"
        echo "  Apply it to the running services:"
        echo "    docker compose -f docker-compose-osc.yaml up -d ccowmcpclient ccowmcpbridge"
        exit 0
    fi

    print_banner

    # Ask user to select setup mode first
    select_setup_mode

    if [ "$SETUP_MODE" = "full" ]; then
        log_info "Starting Open Security Compliance MCP + No-Code UI Setup..."
    else
        log_info "Starting Open Security Compliance No-Code UI Setup..."
    fi
    echo ""

    # Pre-flight checks (common)
    cow_engine_detect || exit 1
    if [ "$COW_ENGINE" = "podman" ]; then
        log_info "Using Podman (docker CLI and compose are pointed at Podman's socket)"
        cow_engine_prepare_vm
    fi
    check_docker
    check_privileges
    check_docker_compose
    check_system_requirements

    # LLM provider, model and the MCP client/bridge secret only for full mode
    if [ "$SETUP_MODE" = "full" ]; then
        check_llm_provider
        ensure_goose_server_secret
    fi

    check_minio_credentials
    check_ssl_certificates
    check_env_files

    # Persist setup mode to env file so the webserver can toggle MCP UI
    ENV_FILE="${SCRIPT_DIR}/etc/userconfig.env"
    if [ "$SETUP_MODE" = "full" ]; then
        update_env_variable "$ENV_FILE" "MCP_ENABLED" "true" "# Setup mode: true = MCP + No-Code UI, false = No-Code UI only"
    else
        update_env_variable "$ENV_FILE" "MCP_ENABLED" "false" "# Setup mode: true = MCP + No-Code UI, false = No-Code UI only"
    fi
    export MCP_ENABLED
    log_info "MCP_ENABLED set to: $([ "$SETUP_MODE" = "full" ] && echo "true" || echo "false")"

    echo ""
    log_info "All pre-flight checks passed!"
    echo ""

    # Display summary based on mode
    if [ "$SETUP_MODE" = "full" ]; then
        echo -e "${CYAN}Setup Summary (MCP + No-Code UI):${NC}"
        echo "  Services to be deployed: 7"
        echo "    1. Web UI (oscwebserver)"
        echo "    2. Reverse Proxy (oscreverseproxy)"
        echo "    3. API Service (oscapiservice)"
        echo "    4. Storage Service (cowstorage/MinIO)"
        echo "    5. MCP Client Integration (ccowmcpclient)"
        echo "    6. MCP Bridge Service (ccowmcpbridge)"
        echo "    7. MCP Service (oscmcpservice)"
    else
        echo -e "${CYAN}Setup Summary (No-Code UI Only):${NC}"
        echo "  Services to be deployed: 4"
        echo "    1. Web UI (oscwebserver)"
        echo "    2. Reverse Proxy (oscreverseproxy)"
        echo "    3. API Service (oscapiservice)"
        echo "    4. Storage Service (cowstorage/MinIO)"
    fi
    echo ""

    # Confirm before proceeding
    read -p "Proceed with Open Security Compliance setup? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log_info "Setup cancelled by user"
        exit 0
    fi

    # Host folders the compose files bind-mount; Podman does not create them on its own
    create_directories

    # Setup process based on mode
    if [ "$SETUP_MODE" = "full" ]; then
        cleanup_docker
        build_services
        start_services
        wait_for_services
        show_service_status
        show_mcp_info

        log_success "Open Security Compliance setup completed successfully!"
        echo ""
        log_info "Next steps:"
        echo "  1. Access the Web UI at https://localhost:${OSC_HTTPS_PORT:-443}"
        echo "  2. Create rules manually or using MCP mode"
        echo "  3. Configure external MCP clients (Goose/Claude) at http://localhost:${OSC_MCP_PORT:-45678}"
        echo "  4. Check the README for detailed usage instructions"
    else
        cleanup_docker_nocode
        build_services_nocode
        start_services_nocode
        wait_for_services_nocode
        show_service_status
        show_nocode_info

        log_success "Open Security Compliance No-Code UI setup completed successfully!"
        echo ""
        log_info "Next steps:"
        echo "  1. Access the Web UI at https://localhost:${OSC_HTTPS_PORT:-443}"
        echo "  2. Create and manage rules using the No-Code web interface"
        echo "  3. To enable AI/MCP features later, re-run this setup with option 1"
    fi
}

# Trap errors
trap 'log_error "Setup failed at line $LINENO. Check the error messages above."' ERR

# Run main function
main "$@"