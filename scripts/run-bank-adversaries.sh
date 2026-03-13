#!/usr/bin/env bash
# =============================================================================
# TIBER/DORA Bank Purple Team - Adversary Orchestrator
# Fuehrt alle 6 Banking-Adversary-Profile sequentiell aus und publiziert zu Splunk
# =============================================================================
set -euo pipefail

# --- Konfiguration ---
CALDERA_API="${CALDERA_API:-http://localhost:8888/api/v2}"
CALDERA_API_KEY="${CALDERA_API_KEY:-DEIN_API_KEY_HIER}"
PLANNER="atomic"
GROUP="red"
JITTER="2/8"
MAX_WAIT=2400  # 40 Minuten pro Operation
LOG_DIR="/var/log/caldera-automation"
LOG_FILE="${LOG_DIR}/bank-adversaries-$(date +%Y%m%d-%H%M).log"

mkdir -p "$LOG_DIR"

# Banking-Adversary-Profile (ID → Name)
declare -A BANK_ADVERSARIES
BANK_ADVERSARIES=(
    ["b4nk-r4ns-0001-aaaa-000000000001"]="TIBER-Bank-Ransomware-Chain"
    ["b4nk-4pt3-0002-bbbb-000000000002"]="TIBER-Bank-APT-Espionage"
    ["b4nk-1ns1-0003-cccc-000000000003"]="TIBER-Bank-Insider-Threat"
    ["b4nk-l4tm-0004-dddd-000000000004"]="TIBER-Bank-Lateral-Movement"
    ["b4nk-3v4s-0005-eeee-000000000005"]="TIBER-Bank-Defense-Evasion"
    ["b4nk-3xf1-0006-ffff-000000000006"]="TIBER-Bank-Data-Exfiltration"
)

# Ausfuehrungsreihenfolge (von Recon zu Impact)
EXECUTION_ORDER=(
    "b4nk-3v4s-0005-eeee-000000000005"  # 1. Defense Evasion - zuerst Erkennung testen
    "b4nk-l4tm-0004-dddd-000000000004"  # 2. Lateral Movement
    "b4nk-4pt3-0002-bbbb-000000000002"  # 3. APT Espionage
    "b4nk-1ns1-0003-cccc-000000000003"  # 4. Insider Threat
    "b4nk-3xf1-0006-ffff-000000000006"  # 5. Data Exfiltration
    "b4nk-r4ns-0001-aaaa-000000000001"  # 6. Ransomware - als letztes (destruktiv)
)

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

# --- Pruefe ob Agents online sind ---
check_agents() {
    log "Pruefe ob Caldera-Agents online sind..."
    local agents
    agents=$(curl -sk -H "KEY: ${CALDERA_API_KEY}" "${CALDERA_API}/agents" 2>/dev/null) || {
        log "FEHLER: Caldera API nicht erreichbar"
        return 1
    }
    local trusted_count
    trusted_count=$(echo "$agents" | jq '[.[] | select(.trusted==true)] | length' 2>/dev/null) || trusted_count=0

    if [[ $trusted_count -eq 0 ]]; then
        log "FEHLER: Keine vertrauenswuerdigen Agents online. Breche ab."
        return 1
    fi
    log "Online Agents: $trusted_count (trusted)"
    return 0
}

# --- Operation starten ---
start_operation() {
    local adv_id="$1"
    local adv_name="$2"
    local op_name="Bank-${adv_name}-$(date +%H%M)"

    log "Starte Operation: $op_name (Adversary: $adv_name)"

    local response
    response=$(curl -sk -X POST \
        -H "KEY: ${CALDERA_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"${op_name}\",
            \"adversary\": {\"adversary_id\": \"${adv_id}\"},
            \"group\": \"${GROUP}\",
            \"planner\": {\"id\": \"${PLANNER}\"},
            \"auto_close\": true,
            \"state\": \"running\",
            \"jitter\": \"${JITTER}\"
        }" \
        "${CALDERA_API}/operations" 2>/dev/null)

    local op_id
    op_id=$(echo "$response" | jq -r '.id // empty' 2>/dev/null)

    if [[ -z "$op_id" ]]; then
        log "FEHLER: Operation konnte nicht gestartet werden fuer $adv_name"
        log "API Response: $response"
        return 1
    fi

    log "Operation gestartet: $op_id"
    echo "$op_id"
}

# --- Auf Operation warten ---
wait_for_operation() {
    local op_id="$1"
    local op_name="$2"
    local waited=0

    while [[ $waited -lt $MAX_WAIT ]]; do
        sleep 15
        waited=$((waited + 15))

        local state
        state=$(curl -sk -H "KEY: ${CALDERA_API_KEY}" \
            "${CALDERA_API}/operations/${op_id}" 2>/dev/null | \
            jq -r '.state // "unknown"' 2>/dev/null) || state="error"

        if [[ "$state" == "finished" ]] || [[ "$state" == "out_of_time" ]] || [[ "$state" == "cleanup" ]]; then
            log "Operation $op_name abgeschlossen: $state (${waited}s)"
            return 0
        fi

        # Fortschritt alle 60 Sekunden ausgeben
        if [[ $((waited % 60)) -eq 0 ]]; then
            local chain_count
            chain_count=$(curl -sk -H "KEY: ${CALDERA_API_KEY}" \
                "${CALDERA_API}/operations/${op_id}" 2>/dev/null | \
                jq '.chain | length' 2>/dev/null) || chain_count="?"
            log "  Warte auf $op_name... Status: $state, Commands: $chain_count (${waited}s/${MAX_WAIT}s)"
        fi
    done

    log "WARNUNG: Timeout fuer Operation $op_name nach ${MAX_WAIT}s"
    return 1
}

# --- Hauptprogramm ---
main() {
    log "================================================================"
    log "TIBER/DORA Bank Purple Team - Adversary Orchestrator"
    log "================================================================"
    log "Caldera API: $CALDERA_API"
    log "Planner: $PLANNER | Group: $GROUP | Jitter: $JITTER"
    log "Adversary-Profile: ${#BANK_ADVERSARIES[@]}"
    log "================================================================"

    check_agents || exit 1

    local succeeded=0
    local failed=0
    local total=${#EXECUTION_ORDER[@]}

    for adv_id in "${EXECUTION_ORDER[@]}"; do
        local adv_name="${BANK_ADVERSARIES[$adv_id]}"
        log ""
        log "--- [$((succeeded + failed + 1))/$total] $adv_name ---"

        local op_id
        op_id=$(start_operation "$adv_id" "$adv_name") || {
            failed=$((failed + 1))
            continue
        }

        if wait_for_operation "$op_id" "$adv_name"; then
            succeeded=$((succeeded + 1))
        else
            failed=$((failed + 1))
        fi

        # Kurze Pause zwischen Operationen
        sleep 5
    done

    log ""
    log "================================================================"
    log "Alle Operationen abgeschlossen: $succeeded/$total erfolgreich, $failed fehlgeschlagen"
    log "================================================================"

    # Ergebnisse nach Splunk publizieren
    log "Publiziere Ergebnisse nach Splunk..."
    /opt/caldera-splunk/publish-to-splunk.sh 2>&1 | tee -a "$LOG_FILE"

    log "================================================================"
    log "Bank Purple Team Test abgeschlossen."
    log "Dashboard: Splunk → TIBER/DORA Bank Purple Team Dashboard"
    log "================================================================"
}

main "$@"
