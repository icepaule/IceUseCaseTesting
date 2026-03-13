#!/usr/bin/env bash
# =============================================================================
# Installiert die Caldera Bank SIEM App auf Splunk via REST API
# Erstellt Indexes, Lookups, Saved Searches und Dashboard remote
# Ziel: Splunk SPLUNK_IP
# =============================================================================
set -euo pipefail

SPLUNK_HOST="${SPLUNK_HOST:-SPLUNK_IP}"
SPLUNK_MGMT_PORT="${SPLUNK_MGMT_PORT:-8089}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-DEIN_HEC_TOKEN_HIER}"
BASE_URL="https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}"
APP_NAME="caldera_bank_siem"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

if [[ -z "$SPLUNK_PASS" ]]; then
    echo "Bitte Splunk Admin-Passwort angeben:"
    echo "  export SPLUNK_PASS='dein_passwort'"
    echo "  $0"
    exit 1
fi

CURL_AUTH="-u ${SPLUNK_USER}:${SPLUNK_PASS}"

# --- 1. App erstellen ---
log "Erstelle Splunk App: $APP_NAME"
curl -sk $CURL_AUTH -X POST "${BASE_URL}/services/apps/local" \
    -d "name=${APP_NAME}" \
    -d "label=Caldera Bank SIEM" \
    -d "visible=true" \
    -d "author=PurpleTeam" 2>/dev/null || log "App existiert bereits"

# --- 2. Indexes erstellen ---
log "Erstelle Index: caldera"
curl -sk $CURL_AUTH -X POST "${BASE_URL}/services/data/indexes" \
    -d "name=caldera" \
    -d "datatype=event" \
    -d "maxTotalDataSizeMB=10240" 2>/dev/null || log "Index caldera existiert bereits"

log "Erstelle Index: siem_summary"
curl -sk $CURL_AUTH -X POST "${BASE_URL}/services/data/indexes" \
    -d "name=siem_summary" \
    -d "datatype=event" \
    -d "maxTotalDataSizeMB=5120" 2>/dev/null || log "Index siem_summary existiert bereits"

# --- 3. Lookup hochladen ---
log "Lade MITRE-Lookup hoch..."
curl -sk $CURL_AUTH -X POST "${BASE_URL}/servicesNS/nobody/${APP_NAME}/data/lookup-table-files" \
    -F "name=mitre_attack_bank_mapping.csv" \
    -F "eai:data=@/opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv" 2>/dev/null || \
    log "Lookup Upload Fehler - ggf. manuell hochladen"

# --- 4. Lookup-Definition erstellen ---
log "Erstelle Lookup-Definition..."
curl -sk $CURL_AUTH -X POST "${BASE_URL}/servicesNS/nobody/${APP_NAME}/data/transforms/lookups" \
    -d "name=mitre_attack_bank_mapping" \
    -d "filename=mitre_attack_bank_mapping.csv" \
    -d "case_sensitive_match=false" 2>/dev/null || log "Lookup-Def existiert bereits"

# --- 5. HEC Token pruefen/erstellen ---
log "Pruefe HEC-Konfiguration..."
curl -sk $CURL_AUTH -X POST "${BASE_URL}/services/data/inputs/http" \
    -d "name=caldera_bank" \
    -d "index=caldera" \
    -d "indexes=caldera,siem_summary" \
    -d "sourcetype=caldera:command:enriched" \
    -d "token=${SPLUNK_HEC_TOKEN}" \
    -d "disabled=0" 2>/dev/null || log "HEC Input existiert bereits"

# HEC aktivieren
curl -sk $CURL_AUTH -X POST "${BASE_URL}/services/data/inputs/http/http" \
    -d "disabled=0" \
    -d "enableSSL=0" 2>/dev/null || true

# --- 6. Saved Searches (SIEM UseCases) installieren ---
log "Installiere SIEM UseCases als Saved Searches..."

# Funktion zum Erstellen eines Saved Search
create_saved_search() {
    local name="$1"
    local search="$2"
    local cron="$3"
    local severity="$4"
    local description="$5"

    curl -sk $CURL_AUTH -X POST \
        "${BASE_URL}/servicesNS/nobody/${APP_NAME}/saved/searches" \
        -d "name=${name}" \
        --data-urlencode "search=${search}" \
        -d "cron_schedule=${cron}" \
        -d "is_scheduled=1" \
        -d "dispatch.earliest_time=-15m" \
        -d "dispatch.latest_time=now" \
        -d "alert.severity=${severity}" \
        -d "description=${description}" \
        -d "disabled=0" 2>/dev/null || log "  Saved Search '${name}' existiert bereits"
}

# UC-BANK-001
create_saved_search \
    "UC-BANK-001 - Credential Dumping Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1003*" OR technique_id="T1040*" OR technique_id="T1552*" OR command_decoded="*mimikatz*" OR command_decoded="*procdump*" OR command_decoded="*lsass*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity siem_usecase_name | eval usecase_id="UC-BANK-001", usecase_name="Credential Dumping Detection", alert_severity="critical" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-001"' \
    "*/5 * * * *" "5" \
    "[CRITICAL] Erkennung von Credential-Dumping. MITRE T1003/T1040/T1552. DORA Art.25."

# UC-BANK-002
create_saved_search \
    "UC-BANK-002 - Privilege Escalation Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1548*" OR technique_id="T1134*" OR technique_id="T1574*" OR command_decoded="*UAC*" OR command_decoded="*DLL*hijack*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-002", usecase_name="Privilege Escalation Detection", alert_severity="critical" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-002"' \
    "*/5 * * * *" "5" \
    "[CRITICAL] Privilege Escalation. MITRE T1548/T1134/T1574. DORA Art.25."

# UC-BANK-003
create_saved_search \
    "UC-BANK-003 - Network Reconnaissance Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1016*" OR technique_id="T1018*" OR technique_id="T1049*" OR technique_id="T1057*" OR technique_id="T1082*" OR technique_id="T1087*" OR technique_id="T1482*") | bin _time span=10m | stats count as recon_count dc(technique_id) as technique_diversity values(technique_id) as techniques values(ability_name) as abilities by _time operation_name paw host | where recon_count>=3 OR technique_diversity>=2 | eval usecase_id="UC-BANK-003", usecase_name="Network Reconnaissance Detection", alert_severity=if(technique_diversity>=4,"critical","high") | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-003"' \
    "*/5 * * * *" "4" \
    "[HIGH] Netzwerk-Reconnaissance. MITRE T1016-T1087/T1482. DORA Art.25."

# UC-BANK-004
create_saved_search \
    "UC-BANK-004 - Lateral Movement Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1021*" OR technique_id="T1570*" OR command_decoded="*net use*" OR command_decoded="*psexec*" OR command_decoded="*winrm*" OR command_decoded="*scp*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-004", usecase_name="Lateral Movement Detection", alert_severity="critical" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-004"' \
    "*/5 * * * *" "5" \
    "[CRITICAL] Lateral Movement. MITRE T1021/T1570. DORA Art.25."

# UC-BANK-005
create_saved_search \
    "UC-BANK-005 - Suspicious Execution Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1059*" OR technique_id="T1047*" OR technique_id="T1569*" OR command_decoded="*powershell*-enc*" OR command_decoded="*invoke-expression*" OR command_decoded="*sc create*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-005", usecase_name="Suspicious Execution Detection", alert_severity="high" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-005"' \
    "*/5 * * * *" "4" \
    "[HIGH] Verdaechtige Befehlsausfuehrung. MITRE T1059/T1047/T1569."

# UC-BANK-006
create_saved_search \
    "UC-BANK-006 - Data Exfiltration Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1041*" OR technique_id="T1048*" OR technique_id="T1029*" OR technique_id="T1030*" OR technique_id="T1567*" OR technique_id="T1537*" OR command_decoded="*exfil*" OR command_decoded="*ftp*put*" OR command_decoded="*github*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-006", usecase_name="Data Exfiltration Detection", alert_severity="critical" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-006"' \
    "*/5 * * * *" "5" \
    "[CRITICAL] Datenexfiltration. MITRE T1041/T1048/T1567. DORA Art.25."

# UC-BANK-007
create_saved_search \
    "UC-BANK-007 - Defense Evasion Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1562*" OR technique_id="T1055*" OR technique_id="T1497*" OR command_decoded="*Disable*Defender*" OR command_decoded="*inject*" OR command_decoded="*bypass*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-007", usecase_name="Defense Evasion Detection", alert_severity="critical" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-007"' \
    "*/5 * * * *" "5" \
    "[CRITICAL] Defense Evasion. MITRE T1562/T1055/T1497. DORA Art.25."

# UC-BANK-008
create_saved_search \
    "UC-BANK-008 - Persistence Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1053*" OR technique_id="T1136*" OR technique_id="T1543*" OR command_decoded="*crontab*" OR command_decoded="*schtasks*" OR command_decoded="*sc create*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-008", usecase_name="Persistence Detection", alert_severity="high" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-008"' \
    "*/5 * * * *" "4" \
    "[HIGH] Persistenz. MITRE T1053/T1136/T1543. DORA Art.25."

# UC-BANK-009
create_saved_search \
    "UC-BANK-009 - Log Tampering Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1070*" OR command_decoded="*wevtutil*cl*" OR command_decoded="*Clear-EventLog*" OR command_decoded="*history*-c*" OR command_decoded="*rm*bash_history*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-009", usecase_name="Log Tampering Detection", alert_severity="critical" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-009"' \
    "*/5 * * * *" "5" \
    "[CRITICAL] Log-Tampering. MITRE T1070. DORA Art.25. MaRisk AT 7.2."

# UC-BANK-010
create_saved_search \
    "UC-BANK-010 - Sensitive Data Access Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1005*" OR technique_id="T1074*" OR technique_id="T1113*" OR technique_id="T1115*" OR technique_id="T1119*" OR technique_id="T1560*" OR command_decoded="*stage*" OR command_decoded="*compress*" OR command_decoded="*screenshot*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-010", usecase_name="Sensitive Data Access Detection", alert_severity="high" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-010"' \
    "*/5 * * * *" "4" \
    "[HIGH] Sensible Datenzugriffe. MITRE T1005/T1074/T1119/T1560."

# UC-BANK-011
create_saved_search \
    "UC-BANK-011 - C2 Communication Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1071*" OR technique_id="T1105*" OR command_decoded="*ragdoll*" OR command_decoded="*beacon*" OR command_decoded="*certutil*urlcache*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-011", usecase_name="C2 Communication Detection", alert_severity="critical" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-011"' \
    "*/5 * * * *" "5" \
    "[CRITICAL] C2-Kommunikation. MITRE T1071/T1105. DORA Art.25."

# UC-BANK-012
create_saved_search \
    "UC-BANK-012 - Ransomware Detection" \
    'index=caldera sourcetype="caldera:command:enriched" (technique_id="T1486*" OR technique_id="T1489*" OR technique_id="T1491*" OR command_decoded="*encrypt*" OR command_decoded="*ransom*" OR command_decoded="*vssadmin*delete*") | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity | eval usecase_id="UC-BANK-012", usecase_name="Ransomware Detection", alert_severity="critical" | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id=UC-BANK-012"' \
    "*/5 * * * *" "5" \
    "[CRITICAL] Ransomware. MITRE T1486/T1489/T1491. DORA Art.19."

# UC-BANK-015 - Kill Chain Correlation (Meta)
create_saved_search \
    "UC-BANK-015 - Kill Chain Correlation" \
    'index=siem_summary sourcetype="siem:usecase:triggered" | rex field=_raw "usecase_id=(?<triggered_usecase>UC-BANK-\d+)" | bin _time span=30m | stats dc(triggered_usecase) as usecase_count values(triggered_usecase) as triggered_usecases values(usecase_name) as usecase_names by _time host operation_name | where usecase_count>=3 | eval usecase_id="UC-BANK-015", usecase_name="Kill Chain Correlation", alert_severity="critical" | collect index=siem_summary sourcetype="siem:usecase:killchain" marker="usecase_id=UC-BANK-015"' \
    "*/10 * * * *" "5" \
    "[CRITICAL] Kill-Chain-Korrelation. Erkennt mehrphasige Angriffe. DORA Art.25/26."

log "Alle Saved Searches installiert."

# --- 7. Dashboard installieren ---
log "Installiere Dashboard..."
DASHBOARD_XML=$(cat /opt/caldera-splunk/dashboards/bank_purple_team_dashboard.xml)

curl -sk $CURL_AUTH -X POST \
    "${BASE_URL}/servicesNS/nobody/${APP_NAME}/data/ui/views" \
    -d "name=bank_purple_team" \
    --data-urlencode "eai:data=${DASHBOARD_XML}" 2>/dev/null || \
    log "Dashboard existiert bereits - aktualisiere..."

curl -sk $CURL_AUTH -X POST \
    "${BASE_URL}/servicesNS/nobody/${APP_NAME}/data/ui/views/bank_purple_team" \
    --data-urlencode "eai:data=${DASHBOARD_XML}" 2>/dev/null || true

log ""
log "================================================================"
log "Installation abgeschlossen!"
log ""
log "Splunk Dashboard: https://${SPLUNK_HOST}/app/${APP_NAME}/bank_purple_team"
log ""
log "Naechste Schritte:"
log "  1. Splunk neu starten: splunk restart"
log "  2. Caldera starten und Agents deployen"
log "  3. Tests ausfuehren: /opt/caldera-splunk/run-bank-adversaries.sh"
log "  4. Ergebnisse publizieren: /opt/caldera-splunk/publish-to-splunk.sh"
log "================================================================"
