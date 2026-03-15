#!/usr/bin/env bash
# =============================================================================
# Caldera Scheduled Test Runner
# Fuehrt alle Bank-Adversary-Profile 3x taeglich aus und prueft SIEM-Compliance
# Sendet Alerts per Mail bei nicht-getriggerten UseCases
# =============================================================================
set -euo pipefail

# --- Konfiguration ---
CALDERA_API="${CALDERA_API:-http://localhost:8888/api/v2}"
CALDERA_API_KEY="${CALDERA_API_KEY:-<API_KEY>}"
BATCH_PLANNER="788107d5-dc1e-4204-9269-38df0186d3e7"
SPLUNK_HOST="${SPLUNK_HOST:-<SPLUNK_HOST>}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-<PASSWORD>}"
ALERT_EMAIL="${ALERT_EMAIL:-alert@example.com}"
LOG_DIR="/var/log/caldera-splunk"
COMPLIANCE_FILE="/opt/caldera-splunk/compliance-status.json"
PUBLISH_SCRIPT="/opt/caldera-splunk/publish-to-splunk.sh"
MAX_WAIT=1800  # 30 min max per batch

mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/scheduled-run-$(date +%Y%m%d-%H%M).log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2; }

# --- Phase 1: Agents pruefen ---
check_agents() {
    log "=== Phase 1: Agent-Pruefung ==="
    local agents
    agents=$(curl -s -H "KEY: $CALDERA_API_KEY" "$CALDERA_API/agents" 2>/dev/null)
    local count
    count=$(echo "$agents" | python3 -c "import sys,json; a=json.load(sys.stdin); print(len([x for x in a if x.get('group')=='claude']))" 2>/dev/null || echo "0")

    if [ "$count" -lt 1 ]; then
        log_error "Keine aktiven Agents in Gruppe 'claude' gefunden!"
        send_alert "KEINE AGENTS" "Es sind keine Caldera-Agents aktiv. Scheduled Tests koennen nicht ausgefuehrt werden."
        exit 1
    fi
    log "Aktive Agents: $count"
}

# --- Phase 2: Adversary-Profile ausfuehren ---
run_adversaries() {
    log "=== Phase 2: Adversary-Profile starten ==="
    local run_id
    run_id="sched-$(date +%Y%m%d-%H%M)"

    # Alle Bank/TIBER Profile holen
    local adversaries
    adversaries=$(curl -s -H "KEY: $CALDERA_API_KEY" "$CALDERA_API/adversaries" 2>/dev/null)

    # Operationen starten
    local op_ids=()
    while IFS= read -r line; do
        local adv_id adv_name
        adv_id=$(echo "$line" | cut -d'|' -f1)
        adv_name=$(echo "$line" | cut -d'|' -f2)

        local op_name="${run_id}-${adv_name}"
        local payload
        payload=$(cat <<EOJSON
{
    "name": "$op_name",
    "adversary": {"adversary_id": "$adv_id"},
    "planner": {"id": "$BATCH_PLANNER"},
    "group": "claude",
    "auto_close": false,
    "state": "running",
    "obfuscator": "plain-text",
    "jitter": "2/8"
}
EOJSON
)
        local resp
        resp=$(curl -s -X POST -H "KEY: $CALDERA_API_KEY" -H "Content-Type: application/json" \
            -d "$payload" "$CALDERA_API/operations" 2>/dev/null)

        local op_id
        op_id=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")

        if [ -n "$op_id" ]; then
            op_ids+=("$op_id")
            log "  Gestartet: $adv_name -> $op_id"
        else
            log_error "  Fehler bei: $adv_name"
        fi
        sleep 1
    done < <(echo "$adversaries" | python3 -c "
import sys, json
advs = json.load(sys.stdin)
for a in sorted(advs, key=lambda x: x['name']):
    if a['name'].startswith('Bank-') or a['name'].startswith('TIBER-Bank-'):
        print(f\"{a['adversary_id']}|{a['name']}\")
" 2>/dev/null)

    log "Gestartete Operationen: ${#op_ids[@]}"

    # Warten auf Abschluss
    log "Warte auf Operationsabschluss (max ${MAX_WAIT}s)..."
    local elapsed=0
    while [ $elapsed -lt $MAX_WAIT ]; do
        sleep 60
        elapsed=$((elapsed + 60))

        local running=0
        for op_id in "${op_ids[@]}"; do
            local state
            state=$(curl -s -H "KEY: $CALDERA_API_KEY" "$CALDERA_API/operations/$op_id" 2>/dev/null \
                | python3 -c "import sys,json; d=json.load(sys.stdin); c=d.get('chain',[]); print(sum(1 for x in c if x.get('status',0)==-3))" 2>/dev/null || echo "0")
            running=$((running + state))
        done

        log "  ${elapsed}s: $running Links noch aktiv"
        if [ "$running" -eq 0 ]; then
            log "  Alle Operationen abgeschlossen"
            break
        fi
    done

    # Operationen stoppen falls noetig
    for op_id in "${op_ids[@]}"; do
        curl -s -X PATCH -H "KEY: $CALDERA_API_KEY" -H "Content-Type: application/json" \
            -d '{"state":"cleanup"}' "$CALDERA_API/operations/$op_id" >/dev/null 2>&1 || true
    done
    log "Alle Operationen gestoppt"
}

# --- Phase 3: Nach Splunk publizieren ---
publish_results() {
    log "=== Phase 3: Ergebnisse nach Splunk publizieren ==="
    if [ -x "$PUBLISH_SCRIPT" ]; then
        "$PUBLISH_SCRIPT" >> "$LOG_FILE" 2>&1
        log "Publish abgeschlossen"
    else
        log_error "Publish-Script nicht gefunden: $PUBLISH_SCRIPT"
    fi
}

# --- Phase 4: Compliance pruefen ---
check_compliance() {
    log "=== Phase 4: SIEM UseCase Compliance pruefen ==="

    python3 << 'PYEOF'
import csv, json, os, subprocess, sys, datetime, urllib3
import requests
urllib3.disable_warnings()

SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "<SPLUNK_HOST>")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "<PASSWORD>")
LOOKUP_FILE = "/opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv"
COMPLIANCE_FILE = "/opt/caldera-splunk/compliance-status.json"
ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "alert@example.com")

# Alle definierten UseCases laden
usecases = {}
with open(LOOKUP_FILE) as f:
    for row in csv.DictReader(f):
        uc_id = row["siem_usecase_id"]
        if uc_id not in usecases:
            usecases[uc_id] = {
                "id": uc_id,
                "name": row["siem_usecase_name"],
                "techniques": [],
                "severity": row["severity"],
                "dora": row["dora_article"],
                "tactic": row["tactic"],
            }
        usecases[uc_id]["techniques"].append(row["technique_id"])

# Splunk abfragen: Welche UseCases haben in 24h getriggert?
search = 'search index=siem_summary sourcetype="siem:usecase:triggered" earliest=-24h latest=now | stats count as triggers latest(_time) as last_trigger by usecase_id | outputmode=json'
try:
    resp = requests.post(
        f"https://{SPLUNK_HOST}:8089/services/search/jobs",
        auth=(SPLUNK_USER, SPLUNK_PASS),
        data={"search": search, "output_mode": "json", "exec_mode": "oneshot"},
        verify=False, timeout=60
    )
    triggered = {}
    for r in resp.json().get("results", []):
        triggered[r["usecase_id"]] = {
            "count": int(r["triggers"]),
            "last": r.get("last_trigger", "")
        }
except Exception as e:
    print(f"[!] Splunk-Abfrage fehlgeschlagen: {e}")
    triggered = {}

# Compliance berechnen
now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
failed = []
passed = []
for uc_id, uc in sorted(usecases.items()):
    if uc_id in triggered and triggered[uc_id]["count"] > 0:
        uc["status"] = "PASSED"
        uc["triggers"] = triggered[uc_id]["count"]
        uc["last_trigger"] = triggered[uc_id]["last"]
        passed.append(uc)
    else:
        uc["status"] = "FAILED"
        uc["triggers"] = 0
        uc["last_trigger"] = "Nie"
        failed.append(uc)

total = len(usecases)
pass_count = len(passed)
fail_count = len(failed)
rate = round(pass_count / total * 100, 1) if total > 0 else 0

compliance = {
    "timestamp": now,
    "total_usecases": total,
    "passed": pass_count,
    "failed": fail_count,
    "compliance_rate": rate,
    "failed_usecases": [{"id": u["id"], "name": u["name"], "severity": u["severity"],
                         "dora": u["dora"], "techniques": u["techniques"]} for u in failed],
    "passed_usecases": [u["id"] for u in passed]
}

with open(COMPLIANCE_FILE, "w") as f:
    json.dump(compliance, f, indent=2)

print(f"[+] Compliance: {pass_count}/{total} PASSED ({rate}%), {fail_count} FAILED")

# Email bei Failures
if failed:
    subject = f"[COMPLIANCE ALERT] {fail_count} SIEM UseCases FAILED - Caldera Bank Purple Team"
    body = f"""Caldera Bank Purple Team - SIEM Compliance Report
Zeitpunkt: {now}
Compliance Rate: {rate}% ({pass_count}/{total})

FAILED UseCases ({fail_count}):
"""
    for u in failed:
        body += f"\n  {u['id']}: {u['name']}"
        body += f"\n    Schweregrad: {u['severity']}"
        body += f"\n    DORA: {u['dora']}"
        body += f"\n    Techniken: {', '.join(u['techniques'])}"
        body += f"\n    Letzter Trigger: {u['last_trigger']}"
        body += "\n"

    body += f"""
DORA Art. 25 Anforderung: Alle definierten SIEM-Erkennungsregeln muessen
durch regelmaessige Tests validiert werden.

Massnahmen:
1. Pruefen Sie ob die Caldera-Agents aktiv sind
2. Pruefen Sie ob die Testcases die entsprechenden Techniken abdecken
3. Pruefen Sie die Splunk Saved Searches auf Fehler

Dashboard: http://{SPLUNK_HOST}:8000/app/caldera_bank_siem/bank_purple_team
"""

    try:
        proc = subprocess.run(
            ["mail", "-s", subject, ALERT_EMAIL],
            input=body, capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0:
            print(f"[+] Alert-Mail an {ALERT_EMAIL} gesendet")
        else:
            print(f"[!] Mail-Versand fehlgeschlagen: {proc.stderr[:200]}")
    except FileNotFoundError:
        print("[!] 'mail' nicht installiert - versuche sendmail")
        try:
            msg = f"Subject: {subject}\nTo: {ALERT_EMAIL}\nFrom: caldera-compliance@bank.local\n\n{body}"
            proc = subprocess.run(
                ["sendmail", ALERT_EMAIL],
                input=msg, capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0:
                print(f"[+] Alert via sendmail an {ALERT_EMAIL} gesendet")
            else:
                print(f"[!] sendmail fehlgeschlagen: {proc.stderr[:200]}")
        except FileNotFoundError:
            print("[!] Weder mail noch sendmail verfuegbar")
            print(f"[!] Alert-Body:\n{body}")
    except Exception as e:
        print(f"[!] Mail-Fehler: {e}")
else:
    print(f"[+] Alle {total} UseCases PASSED - keine Alerts noetig")

PYEOF
}

# --- Main ---
main() {
    log "=============================================="
    log "  Caldera Scheduled Test Runner"
    log "  $(date '+%Y-%m-%d %H:%M:%S')"
    log "=============================================="

    check_agents
    run_adversaries
    publish_results

    # Warte 5 Min damit Splunk Saved Searches laufen
    log "Warte 5 Min fuer Splunk Saved Search Ausfuehrung..."
    sleep 300

    check_compliance

    log "=============================================="
    log "  Scheduled Run abgeschlossen"
    log "=============================================="
}

main "$@"
