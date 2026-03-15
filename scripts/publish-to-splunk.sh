#!/usr/bin/env bash
# =============================================================================
# Caldera → Splunk Publisher (Enhanced)
# Publiziert Caldera-Operationsdaten enriched mit MITRE ATT&CK Mapping nach Splunk
# Fuer TIBER-EU/DORA Bank Purple Team Testing
# =============================================================================
set -euo pipefail

# --- Konfiguration ---
CALDERA_API="${CALDERA_API:-http://localhost:8888/api/v2}"
CALDERA_API_KEY="${CALDERA_API_KEY:-<API_KEY>}"
SPLUNK_HEC="${SPLUNK_HEC:-http://<SPLUNK_HOST>:8088/services/collector/event}"
SPLUNK_TOKEN="${SPLUNK_TOKEN:-<HEC_TOKEN>}"
SPLUNK_INDEX="caldera"
LOOKUP_FILE="/opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv"
LOG_DIR="/var/log/caldera-splunk"
LOG_FILE="${LOG_DIR}/publish-$(date +%Y%m%d).log"

mkdir -p "$LOG_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2; }

# --- MITRE-Lookup laden ---
declare -A MITRE_TECHNIQUE_NAME MITRE_TACTIC MITRE_SEVERITY MITRE_USECASE_ID MITRE_USECASE_NAME MITRE_DORA MITRE_BANK_RELEVANCE
load_mitre_lookup() {
    if [[ ! -f "$LOOKUP_FILE" ]]; then
        log_error "MITRE Lookup-Datei nicht gefunden: $LOOKUP_FILE"
        return 1
    fi
    local line_num=0
    while IFS=',' read -r tech_id tech_name tactic severity bank_rel uc_id uc_name dora tiber desc; do
        line_num=$((line_num + 1))
        [[ $line_num -eq 1 ]] && continue  # Header ueberspringen
        MITRE_TECHNIQUE_NAME["$tech_id"]="$tech_name"
        MITRE_TACTIC["$tech_id"]="$tactic"
        MITRE_SEVERITY["$tech_id"]="$severity"
        MITRE_USECASE_ID["$tech_id"]="$uc_id"
        MITRE_USECASE_NAME["$tech_id"]="$uc_name"
        MITRE_DORA["$tech_id"]="$dora"
        MITRE_BANK_RELEVANCE["$tech_id"]="$bank_rel"
    done < "$LOOKUP_FILE"
    log "MITRE Lookup geladen: $((line_num - 1)) Eintraege"
}

# --- Base64-Erkennung und Dekodierung ---
is_base64() {
    local input="$1"
    [[ ${#input} -ge 4 ]] && [[ $((${#input} % 4)) -eq 0 ]] && echo "$input" | grep -qP '^[A-Za-z0-9+/=]+$'
}

decode_command() {
    local raw="$1"
    if is_base64 "$raw" 2>/dev/null; then
        local decoded
        decoded=$(echo "$raw" | base64 -d 2>/dev/null) || decoded="$raw"
        # Pruefen ob dekodierter Inhalt druckbar ist
        if echo "$decoded" | grep -qP '^[\x20-\x7E\s]+$'; then
            echo "$decoded"
        else
            echo "$raw"
        fi
    else
        echo "$raw"
    fi
}

# --- JSON-Safe String ---
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    echo "$s"
}

# --- Splunk HEC Senden ---
send_to_splunk() {
    local sourcetype="$1"
    local event_json="$2"
    local payload="{\"sourcetype\":\"${sourcetype}\",\"index\":\"${SPLUNK_INDEX}\",\"host\":\"caldera\",\"event\":${event_json}}"

    local http_code
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Authorization: Splunk ${SPLUNK_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$SPLUNK_HEC" 2>/dev/null) || true

    if [[ "$http_code" == "200" ]]; then
        return 0
    else
        log_error "Splunk HEC antwortet mit HTTP $http_code fuer sourcetype=$sourcetype"
        return 1
    fi
}

# --- Operationen abrufen und publizieren ---
publish_operations() {
    log "=== Starte Caldera → Splunk Publish ==="

    # Alle Operationen abrufen
    local operations
    operations=$(curl -sk -H "KEY: ${CALDERA_API_KEY}" \
        -H "Content-Type: application/json" \
        "${CALDERA_API}/operations" 2>/dev/null) || {
        log_error "Caldera API nicht erreichbar: ${CALDERA_API}/operations"
        return 1
    }

    local op_count
    op_count=$(echo "$operations" | jq 'length' 2>/dev/null) || op_count=0
    log "Gefundene Operationen: $op_count"

    local total_commands=0
    local total_sent=0
    local total_errors=0

    # Jede Operation verarbeiten
    echo "$operations" | jq -c '.[]' 2>/dev/null | while read -r op; do
        local op_id op_name op_state
        op_id=$(echo "$op" | jq -r '.id // "unknown"')
        op_name=$(echo "$op" | jq -r '.name // "unknown"')
        op_state=$(echo "$op" | jq -r '.state // "unknown"')

        log "Verarbeite Operation: $op_name ($op_id) [Status: $op_state]"

        # Operation-Metadaten publizieren
        send_to_splunk "caldera:operation" "$op" && log "  Operation-Meta gesendet" || true

        # Detaillierte Operationsdaten mit Chain abrufen
        local op_detail
        op_detail=$(curl -sk -H "KEY: ${CALDERA_API_KEY}" \
            -H "Content-Type: application/json" \
            "${CALDERA_API}/operations/${op_id}" 2>/dev/null) || continue

        # Commands (Chain) verarbeiten
        echo "$op_detail" | jq -c '.chain[]? // empty' 2>/dev/null | while read -r link; do
            total_commands=$((total_commands + 1))

            # Felder extrahieren
            local paw host_name pid status ability_name technique_id technique_name
            local command_raw collect_time finish_time

            paw=$(echo "$link" | jq -r '.paw // "unknown"')
            host_name=$(echo "$link" | jq -r '.host // "unknown"')
            pid=$(echo "$link" | jq -r '.pid // 0')
            status=$(echo "$link" | jq -r '.status // -1')
            collect_time=$(echo "$link" | jq -r '.collect // ""')
            finish_time=$(echo "$link" | jq -r '.finish // ""')

            # Ability-Details
            ability_name=$(echo "$link" | jq -r '.ability.name // "unknown"')
            technique_id=$(echo "$link" | jq -r '.ability.technique_id // "unknown"')
            technique_name=$(echo "$link" | jq -r '.ability.technique_name // "unknown"')
            local tactic
            tactic=$(echo "$link" | jq -r '.ability.tactic // "unknown"')

            # Command dekodieren
            command_raw=$(echo "$link" | jq -r '.command // ""')
            local command_decoded
            command_decoded=$(decode_command "$command_raw")
            local command_cleaned
            command_cleaned=$(json_escape "$command_decoded")

            # Keywords extrahieren
            local command_keywords
            command_keywords=$(echo "$command_decoded" | head -c 200 | awk '{print $1" "$2" "$3}')

            # MITRE-Enrichment aus Lookup
            local siem_usecase_id="${MITRE_USECASE_ID[$technique_id]:-}"
            local siem_usecase_name="${MITRE_USECASE_NAME[$technique_id]:-}"
            local severity="${MITRE_SEVERITY[$technique_id]:-unknown}"
            local bank_relevance="${MITRE_BANK_RELEVANCE[$technique_id]:-}"
            local dora_article="${MITRE_DORA[$technique_id]:-}"

            # Artefakt-Typ bestimmen
            local artifact_type="unknown"
            case "$command_decoded" in
                *mimikatz*|*procdump*|*lsass*|*sekurlsa*|*credential*|*password*|*ntds*)
                    artifact_type="credential_artifact" ;;
                *"net use"*|*psexec*|*winrm*|*ssh*|*wmic*|*smbclient*|*mount*)
                    artifact_type="lateral_movement_artifact" ;;
                *crontab*|*schtasks*|*"sc create"*|*persist*|*"reg add"*)
                    artifact_type="persistence_artifact" ;;
                *compress*|*archive*|*zip*|*tar*|*exfil*|*ftp*|*upload*|*curl*)
                    artifact_type="exfiltration_artifact" ;;
                *defender*|*disable*|*bypass*|*inject*|*wevtutil*|*"Clear-EventLog"*)
                    artifact_type="evasion_artifact" ;;
                *whoami*|*ipconfig*|*netstat*|*arp*|*nslookup*|*"net user"*|*systeminfo*|*tasklist*)
                    artifact_type="discovery_artifact" ;;
                *encrypt*|*ransom*|*shutdown*|*kill*|*"stop-service"*|*"rm -rf"*)
                    artifact_type="impact_artifact" ;;
                *screen*|*clipboard*|*keylog*|*capture*|*record*)
                    artifact_type="collection_artifact" ;;
            esac

            # Enriched Event JSON erstellen
            local event_json
            event_json=$(cat <<ENDJSON
{
    "operation_id": "$(json_escape "$op_id")",
    "operation_name": "$(json_escape "$op_name")",
    "operation_state": "$(json_escape "$op_state")",
    "paw": "$(json_escape "$paw")",
    "host": "$(json_escape "$host_name")",
    "pid": $pid,
    "status": $status,
    "collect_time": "$(json_escape "$collect_time")",
    "finish_time": "$(json_escape "$finish_time")",
    "ability_name": "$(json_escape "$ability_name")",
    "technique_id": "$(json_escape "$technique_id")",
    "technique_name": "$(json_escape "$technique_name")",
    "tactic": "$(json_escape "$tactic")",
    "command_raw": "$(json_escape "$command_raw")",
    "command_decoded": "$command_cleaned",
    "command_keywords": "$(json_escape "$command_keywords")",
    "artifact_type": "$artifact_type",
    "siem_usecase_id": "$(json_escape "$siem_usecase_id")",
    "siem_usecase_name": "$(json_escape "$siem_usecase_name")",
    "severity": "$severity",
    "bank_relevance": "$(json_escape "$bank_relevance")",
    "dora_article": "$(json_escape "$dora_article")",
    "correlation_key": "${host_name}_${pid}_${collect_time}"
}
ENDJSON
)

            if send_to_splunk "caldera:command:enriched" "$event_json"; then
                total_sent=$((total_sent + 1))
            else
                total_errors=$((total_errors + 1))
            fi
        done

        log "  Operation $op_name: Commands verarbeitet"
    done

    # Agents publizieren
    log "Publiziere Agent-Daten..."
    local agents
    agents=$(curl -sk -H "KEY: ${CALDERA_API_KEY}" \
        -H "Content-Type: application/json" \
        "${CALDERA_API}/agents" 2>/dev/null) || true

    if [[ -n "$agents" ]]; then
        echo "$agents" | jq -c '.[]' 2>/dev/null | while read -r agent; do
            send_to_splunk "caldera:agent" "$agent" || true
        done
        log "Agent-Daten publiziert"
    fi

    log "=== Publish abgeschlossen ==="
}

# --- Hauptprogramm ---
main() {
    log "========================================"
    log "Caldera Bank SIEM Publisher gestartet"
    log "Caldera API: $CALDERA_API"
    log "Splunk HEC: $SPLUNK_HEC"
    log "========================================"

    load_mitre_lookup || exit 1
    publish_operations

    log "Publisher beendet."
}

main "$@"
