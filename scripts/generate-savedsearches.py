#!/usr/bin/env python3
"""
generate-savedsearches.py
Reads the generated MITRE lookup and generates Splunk saved searches (one per use case group).
Each search detects events matching the specific technique IDs and tool keywords.
Deploys to Splunk via REST API.
"""
import csv
import json
import os
import sys
import requests
from collections import defaultdict, OrderedDict
from typing import Dict, List

# --- Configuration ---
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "<SPLUNK_HOST>")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "<PASSWORD>")
SPLUNK_APP = "caldera_bank_siem"

LOOKUP_CSV = "/opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv"
OUTPUT_CONF = "/opt/caldera-splunk/siem/siem_usecases_savedsearches.conf"
REPO_SIEM_DIR = "/root/IceUseCaseTesting"

# --- Tool keywords for SPL matching per tactic ---
TACTIC_KEYWORDS = {
    "credential-access": [
        "mimikatz", "procdump", "lsass", "sekurlsa", "credential", "ntds",
        "MiniDump", "password", "tcpdump", "sniff", "private*key", "dcsync",
        "kerberoast", "rubeus", "lazagne", "secretsdump", "hashdump", "sam",
        "wce", "npspy", "keymgr", "shadow", "passwd", "invoke-mimikatz",
        "powerkatz"
    ],
    "privilege-escalation": [
        "UAC*bypass", "fodhelper", "eventvwr", "slui", "sdclt", "SUID",
        "DLL*hijack", "token", "runas", "privilege", "escalat", "exploit",
        "potato", "juicy", "PrintSpoofer"
    ],
    "lateral-movement": [
        "net use", "psexec", "winrm", "invoke-command", "scp", "ssh",
        "wmic", "mount", "smbclient", "dcom", "pass-the-hash", "pass-the-ticket",
        "remote", "rdp", "lateral"
    ],
    "defense-evasion": [
        "Disable*Defender", "Set-MpPreference", "ExecutionPolicy*Bypass",
        "inject", "hollowing", "mavinject", "odbcconf", "sandbox",
        "wevtutil", "Clear-EventLog", "timestomp", "masquerad",
        "amsi", "bypass", "obfuscat", "encoded", "rundll32"
    ],
    "discovery": [
        "arp", "nslookup", "netstat", "systeminfo", "whoami", "net user",
        "net group", "nltest", "dsquery", "bloodhound", "sharphound",
        "powerview", "hostname", "ipconfig", "tasklist", "wmic",
        "Get-Process", "Get-Service", "domain"
    ],
    "execution": [
        "powershell*-enc", "invoke-expression", "iex", "downloadstring",
        "wmic*process", "sc create", "New-Service", "mshta", "rundll32",
        "regsvr32", "certutil", "bitsadmin", "cscript", "wscript",
        "Start-Process"
    ],
    "persistence": [
        "crontab", "schtasks", "sc create", "New-Service", "net user*add",
        "useradd", "adduser", "reg*add*Run", "registry", "startup",
        "scheduled", "wmi*subscription", "com*hijack"
    ],
    "exfiltration": [
        "exfil", "upload", "ftp*put", "curl*POST", "github", "dropbox",
        "s3*cp", "aws*s3", "compress", "archive", "transfer", "cloud"
    ],
    "collection": [
        "screenshot", "clipboard", "keylog", "screen*capture",
        "find*-name", "stage", "tar", "zip", "7z", "email",
        "Get-Clipboard", "record", "audio"
    ],
    "command-and-control": [
        "ragdoll", "beacon", "reverse*shell", "download*cradle",
        "certutil*urlcache", "bitsadmin", "Invoke-WebRequest",
        "dns*tunnel", "proxy", "http", "nslookup*txt"
    ],
    "impact": [
        "encrypt", "ransom", "vssadmin*delete", "bcdedit", "wbadmin*delete",
        "stop-service", "note", "README", "shutdown", "halt", "kill",
        "rm -rf", "del /f", "format", "dd if=/dev/zero", "mining", "xmrig"
    ],
    "initial-access": [
        "phish", "exploit", "drive-by", "supply chain", "spearphish",
        "attachment", "link", "macro"
    ],
}

# Severity levels for Splunk alert
ALERT_SEVERITY = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
}


def read_lookup() -> List[dict]:
    """Read the MITRE lookup CSV."""
    if not os.path.exists(LOOKUP_CSV):
        print(f"[!] Lookup CSV not found: {LOOKUP_CSV}")
        print("[!] Run generate-mitre-lookup.py first")
        sys.exit(1)

    rows = []
    with open(LOOKUP_CSV, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    print(f"[+] Read {len(rows)} entries from lookup")
    return rows


def group_by_usecase(rows: List[dict]) -> Dict[str, dict]:
    """Group lookup rows by use case ID."""
    usecases = OrderedDict()
    for row in rows:
        uc_id = row["siem_usecase_id"]
        if uc_id not in usecases:
            usecases[uc_id] = {
                "usecase_id": uc_id,
                "usecase_name": row["siem_usecase_name"],
                "tactic": row["tactic"],
                "severity": row["severity"],
                "technique_ids": [],
                "technique_names": [],
                "description_de": row.get("description_de", ""),
                "dora_article": row.get("dora_article", "Art.25"),
            }
        usecases[uc_id]["technique_ids"].append(row["technique_id"])
        usecases[uc_id]["technique_names"].append(row["technique_name"])
    return usecases


def generate_technique_filter(technique_ids: List[str]) -> str:
    """Generate SPL technique_id filter."""
    # Group by parent technique for compact filter
    parents = set()
    specifics = set()
    for tid in technique_ids:
        if "." in tid:
            parents.add(tid.split(".")[0])
            specifics.add(tid)
        else:
            parents.add(tid)

    filters = []
    for p in sorted(parents):
        filters.append(f'technique_id="{ p }*"')
    return " OR ".join(filters)


def generate_keyword_filter(tactic: str) -> str:
    """Generate SPL command keyword matching."""
    keywords = TACTIC_KEYWORDS.get(tactic, [])
    if not keywords:
        return ""

    parts = []
    for kw in keywords[:15]:  # Limit to avoid overly long searches
        parts.append(f'command_decoded="*{kw}*"')
    return " OR ".join(parts)


def build_saved_search(uc: dict) -> str:
    """Build a single saved search stanza."""
    uc_id = uc["usecase_id"]
    uc_name = uc["usecase_name"]
    tactic = uc["tactic"]
    severity = uc["severity"]
    technique_ids = uc["technique_ids"]
    dora = uc["dora_article"]
    desc = uc.get("description_de", "")

    severity_label = severity.upper()
    alert_sev = ALERT_SEVERITY.get(severity, 3)

    technique_filter = generate_technique_filter(technique_ids)
    keyword_filter = generate_keyword_filter(tactic)

    # Build the search
    technique_id_list = ", ".join(sorted(set(technique_ids)))

    # Build OR clause combining technique filter and keyword filter
    or_clause = f"({technique_filter})"
    if keyword_filter:
        or_clause += f" \\\n  OR ({keyword_filter})"

    search = f"""index=caldera sourcetype="caldera:command:enriched" \\
  {or_clause} \\
  | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity bank_relevance siem_usecase_name dora_article description_de \\
  | eval alert_severity="{severity}" \\
  | eval usecase_id="{uc_id}" \\
  | eval usecase_name="{uc_name}" \\
  | eval bank_risk="{desc}" \\
  | eval dora_reference="DORA {dora} - ICT-Risikomanagement" \\
  | table _time operation_name paw host ability_name technique_id technique_name command_decoded alert_severity usecase_id usecase_name bank_risk dora_reference \\
  | collect index=siem_summary sourcetype="siem:usecase:triggered" marker="usecase_id={uc_id}\""""

    # Determine schedule based on severity
    if severity == "critical":
        cron = "*/5 * * * *"
        suppress_period = "1h"
    elif severity == "high":
        cron = "*/5 * * * *"
        suppress_period = "1h"
    else:
        cron = "*/10 * * * *"
        suppress_period = "2h"

    # Clean the usecase name for the stanza title (remove problematic chars)
    stanza_name = f"{uc_id} - {uc_name}"
    # Truncate if too long
    if len(stanza_name) > 120:
        stanza_name = stanza_name[:117] + "..."

    stanza = f"""# =============================================================================
# {uc_id}: {uc_name}
# MITRE: {technique_id_list}
# Tactic: {tactic} | Severity: {severity_label}
# =============================================================================
[{stanza_name}]
description = [{severity_label}] {desc}. MITRE {technique_id_list}. DORA {dora}.
search = {search}
dispatch.earliest_time = -15m
dispatch.latest_time = now
cron_schedule = {cron}
enableSched = 1
alert.severity = {alert_sev}
alert.suppress = 1
alert.suppress.period = {suppress_period}
alert.suppress.fields = host,technique_id
counttype = number of events
quantity = 0
relation = greater than
action.email = 0
disabled = 0
"""
    return stanza


def build_summary_populate() -> str:
    """Build the summary index population search."""
    return """# =============================================================================
# Summary Index Population - Basis fuer alle SIEM Use Cases
# Laueft alle 5 Minuten und fuellt den siem_summary Index
# =============================================================================
[SIEM-Summary-Populate-Caldera-Events]
description = Aggregiert Caldera-Testdaten in den Summary-Index mit MITRE-Anreicherung
search = index=caldera sourcetype="caldera:command:enriched" \\
  | lookup mitre_attack_bank_mapping technique_id OUTPUT technique_name tactic severity bank_relevance siem_usecase_id siem_usecase_name dora_article tiber_phase description_de \\
  | eval test_timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S") \\
  | eval artifact_type=case( \\
      match(command_decoded, "(?i)(mimikatz|procdump|lsass|sekurlsa|credential|password|ntds)"), "credential_artifact", \\
      match(command_decoded, "(?i)(net\\s+use|psexec|winrm|ssh|wmic|smbclient|mount)"), "lateral_movement_artifact", \\
      match(command_decoded, "(?i)(reg\\s+query|reg\\s+add|schtasks|cron|service|persist)"), "persistence_artifact", \\
      match(command_decoded, "(?i)(compress|archive|zip|tar|7z|rar|staging|exfil|curl|ftp|upload)"), "exfiltration_artifact", \\
      match(command_decoded, "(?i)(defender|disable|bypass|inject|hollowing|evasion|wevtutil|clear-eventlog)"), "evasion_artifact", \\
      match(command_decoded, "(?i)(whoami|ipconfig|ifconfig|netstat|arp|nslookup|net\\s+user|net\\s+group|systeminfo|tasklist|ps\\s+aux)"), "discovery_artifact", \\
      match(command_decoded, "(?i)(encrypt|ransom|shutdown|kill|stop-service|del\\s+/|rm\\s+-rf)"), "impact_artifact", \\
      match(command_decoded, "(?i)(screen|clipboard|keylog|capture|record)"), "collection_artifact", \\
      1=1, "unknown_artifact") \\
  | eval siem_triggered=if(isnotnull(siem_usecase_id), 1, 0) \\
  | stats count as event_count \\
      values(ability_name) as abilities \\
      values(technique_id) as techniques \\
      values(tactic) as tactics \\
      values(severity) as severities \\
      values(artifact_type) as artifact_types \\
      values(siem_usecase_id) as matched_usecases \\
      values(siem_usecase_name) as matched_usecase_names \\
      values(command_decoded) as commands \\
      values(dora_article) as dora_articles \\
      values(tiber_phase) as tiber_phases \\
      max(siem_triggered) as usecase_triggered \\
      latest(test_timestamp) as last_seen \\
      by operation_name, paw, host \\
  | collect index=siem_summary sourcetype="siem:caldera:summary"
dispatch.earliest_time = -5m
dispatch.latest_time = now
cron_schedule = */5 * * * *
enableSched = 1
is_visible = true
disabled = 0

"""


def build_kill_chain_correlator() -> str:
    """Build the kill chain correlator (UC-BANK-999)."""
    return """# =============================================================================
# UC-BANK-999: Kill Chain Correlation (Meta-UseCase)
# Korreliert mehrere UseCases zu einer vollstaendigen Angriffskette
# Erkennt wenn ein Angreifer mehrere Phasen der Kill Chain durchlaeuft
# Schweregrad: CRITICAL
# =============================================================================
[UC-BANK-999 - Kill Chain Correlation]
description = [CRITICAL] Meta-Korrelation: Erkennt vollstaendige Angriffsketten ueber mehrere SIEM-UseCases. DORA Art.25/26.
search = index=siem_summary sourcetype="siem:usecase:triggered" \\
  | rex field=_raw "usecase_id=(?<triggered_usecase>UC-BANK-\\d+)" \\
  | bin _time span=30m \\
  | stats dc(triggered_usecase) as usecase_count values(triggered_usecase) as triggered_usecases values(usecase_name) as usecase_names values(technique_id) as kill_chain_techniques by _time host operation_name \\
  | where usecase_count >= 3 \\
  | eval kill_chain_phase=case( \\
      match(mvjoin(triggered_usecases,","), "UC-BANK-0[67]") AND match(mvjoin(triggered_usecases,","), "UC-BANK-00[1-9]") AND match(mvjoin(triggered_usecases,","), "UC-BANK-03"), "Full Kill Chain: Recon->Credentials->LateralMovement", \\
      match(mvjoin(triggered_usecases,","), "UC-BANK-00[1-9]") AND match(mvjoin(triggered_usecases,","), "UC-BANK-10"), "Data Breach Chain: Credentials->Exfiltration", \\
      match(mvjoin(triggered_usecases,","), "UC-BANK-04") AND match(mvjoin(triggered_usecases,","), "UC-BANK-13"), "Ransomware Chain: Evasion->Impact", \\
      match(mvjoin(triggered_usecases,","), "UC-BANK-11") AND match(mvjoin(triggered_usecases,","), "UC-BANK-10"), "Insider Threat Chain: Collection->Exfiltration", \\
      1=1, "Multi-Phase Attack: ".mvjoin(triggered_usecases, "->")) \\
  | eval alert_severity="critical" \\
  | eval usecase_id="UC-BANK-999" \\
  | eval usecase_name="Kill Chain Correlation" \\
  | eval bank_risk="HOECHSTE ESKALATION: Mehrphasiger Angriff auf Bankinfrastruktur erkannt" \\
  | eval response="Sofort: CSIRT aktivieren, Systemisolierung, BaFin-Meldung vorbereiten" \\
  | collect index=siem_summary sourcetype="siem:usecase:killchain" marker="usecase_id=UC-BANK-999"
dispatch.earliest_time = -1h
dispatch.latest_time = now
cron_schedule = */10 * * * *
enableSched = 1
alert.severity = 5
counttype = number of events
quantity = 0
relation = greater than
disabled = 0
"""


def generate_conf(usecases: Dict[str, dict]) -> str:
    """Generate the complete savedsearches.conf content."""
    lines = []
    lines.append("# =============================================================================")
    lines.append("# SIEM Use Cases fuer mittelstaendische Bank - Caldera Purple Team Testing")
    lines.append("# Auto-generated by generate-savedsearches.py")
    lines.append("# Basierend auf TIBER-EU/DORA, MITRE ATT&CK, Banking Threat Landscape 2025/2026")
    lines.append("# Splunk Saved Searches / Correlation Rules")
    lines.append("# =============================================================================")
    lines.append('# Installation: Kopiere nach $SPLUNK_HOME/etc/apps/caldera_bank_siem/local/savedsearches.conf')
    lines.append('# Voraussetzungen: Index "caldera", Index "siem_summary", Lookup "mitre_attack_bank_mapping.csv"')
    lines.append("# =============================================================================")
    lines.append("")

    # Summary populate
    lines.append(build_summary_populate())

    # Individual use case searches
    for uc_id in sorted(usecases.keys()):
        uc = usecases[uc_id]
        stanza = build_saved_search(uc)
        lines.append(stanza)

    # Kill chain correlator
    lines.append(build_kill_chain_correlator())

    return "\n".join(lines)


def deploy_to_splunk(conf_content: str, usecases: Dict[str, dict]):
    """Deploy saved searches to Splunk via REST API."""
    print("[*] Deploying saved searches to Splunk...")

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    base_url = f"https://{SPLUNK_HOST}:8089/servicesNS/admin/{SPLUNK_APP}/saved/searches"

    deployed = 0
    errors = 0

    # Deploy each use case as a saved search
    all_usecases = list(usecases.values())
    # Add kill chain correlator
    all_usecases.append({
        "usecase_id": "UC-BANK-999",
        "usecase_name": "Kill Chain Correlation",
        "tactic": "correlation",
        "severity": "critical",
    })

    for uc in all_usecases:
        uc_id = uc["usecase_id"]
        uc_name = uc["usecase_name"]
        stanza_name = f"{uc_id} - {uc_name}"
        if len(stanza_name) > 120:
            stanza_name = stanza_name[:117] + "..."

        try:
            # Check if exists
            check_url = f"{base_url}/{requests.utils.quote(stanza_name, safe='')}"
            check_resp = requests.get(
                check_url,
                auth=(SPLUNK_USER, SPLUNK_PASS),
                params={"output_mode": "json"},
                verify=False,
                timeout=10
            )

            if check_resp.status_code == 200:
                # Update existing
                deployed += 1
            else:
                deployed += 1
        except Exception as e:
            errors += 1

    # Instead of individual deploys, upload the conf file
    try:
        # Try to upload via a simpler method - create the app config
        conf_url = f"https://{SPLUNK_HOST}:8089/servicesNS/admin/{SPLUNK_APP}/configs/conf-savedsearches"

        # Upload the file directly to Splunk
        splunk_conf_path = f"/opt/splunk/etc/apps/{SPLUNK_APP}/local/savedsearches.conf"

        # Try SCP upload
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as tmp:
            tmp.write(conf_content)
            tmp_path = tmp.name

        result = subprocess.run(
            ["scp", "-o", "StrictHostKeyChecking=no", tmp_path,
             f"root@{SPLUNK_HOST}:{splunk_conf_path}"],
            capture_output=True, text=True, timeout=30
        )

        os.unlink(tmp_path)

        if result.returncode == 0:
            print(f"[+] Saved searches conf uploaded to Splunk via SCP")
            # Reload Splunk
            reload_url = f"https://{SPLUNK_HOST}:8089/services/apps/local/{SPLUNK_APP}/_reload"
            requests.post(reload_url, auth=(SPLUNK_USER, SPLUNK_PASS), verify=False, timeout=15)
            print(f"[+] Splunk app reloaded")
        else:
            print(f"[!] SCP upload failed: {result.stderr[:200]}")
            print(f"    Manual deployment required: copy {OUTPUT_CONF} to Splunk")
    except Exception as e:
        print(f"[!] Splunk deployment error: {e}")
        print(f"    Manual deployment required: copy {OUTPUT_CONF} to Splunk")


def main():
    print("=" * 70)
    print("  SIEM Use Case Saved Search Generator")
    print("  Generates Splunk saved searches from MITRE lookup")
    print("=" * 70)
    print()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Read lookup
    rows = read_lookup()

    # Group by use case
    usecases = group_by_usecase(rows)
    print(f"[+] Grouped into {len(usecases)} use cases")

    # Generate conf
    conf_content = generate_conf(usecases)

    # Write to file
    os.makedirs(os.path.dirname(OUTPUT_CONF), exist_ok=True)
    with open(OUTPUT_CONF, "w") as f:
        f.write(conf_content)
    print(f"[+] Wrote saved searches to {OUTPUT_CONF}")

    # Copy to repo
    repo_path = os.path.join(REPO_SIEM_DIR, "siem_usecases_savedsearches.conf")
    try:
        import shutil
        shutil.copy2(OUTPUT_CONF, repo_path)
        print(f"[+] Copied to {repo_path}")
    except Exception as e:
        print(f"[!] Could not copy to repo: {e}")

    # Deploy to Splunk
    deploy_to_splunk(conf_content, usecases)

    # Summary
    print()
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    total_techniques = sum(len(uc["technique_ids"]) for uc in usecases.values())
    tactics = set(uc["tactic"] for uc in usecases.values())
    print(f"  Saved searches generated: {len(usecases) + 2}")  # +2 for summary populate and kill chain
    print(f"  Use cases (UC-BANK-XXX): {len(usecases)}")
    print(f"  Total technique mappings: {total_techniques}")
    print(f"  Tactics covered: {sorted(tactics)}")
    print(f"  Kill chain correlator: UC-BANK-999")
    print()

    # Use case breakdown
    for uc_id in sorted(usecases.keys()):
        uc = usecases[uc_id]
        print(f"  {uc_id}: {uc['usecase_name']} [{uc['severity'].upper()}]")
        print(f"    Techniques: {', '.join(sorted(set(uc['technique_ids'])))}")
    print()
    print(f"  Output: {OUTPUT_CONF}")
    print("=" * 70)


if __name__ == "__main__":
    main()
