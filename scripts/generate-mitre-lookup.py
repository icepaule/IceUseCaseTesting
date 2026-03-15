#!/usr/bin/env python3
"""
generate-mitre-lookup.py
Queries all abilities from Caldera API and generates a comprehensive MITRE ATT&CK
lookup CSV with SIEM use case IDs, DORA articles, TIBER phases, and German descriptions.
Outputs to /opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv
"""
import csv
import json
import os
import shutil
import subprocess
import sys
import requests
from collections import defaultdict, OrderedDict
from typing import Dict, List, Tuple

# --- Configuration ---
CALDERA_API = os.environ.get("CALDERA_API", "http://localhost:8888/api/v2")
CALDERA_API_KEY = os.environ.get("CALDERA_API_KEY", "<API_KEY>")
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "<SPLUNK_HOST>")
SPLUNK_USER = os.environ.get("SPLUNK_USER", "admin")
SPLUNK_PASS = os.environ.get("SPLUNK_PASS", "<PASSWORD>")

OUTPUT_CSV = "/opt/caldera-splunk/lookups/mitre_attack_bank_mapping.csv"
REPO_LOOKUP_DIR = "/root/IceUseCaseTesting/caldera"

HEADERS = {
    "KEY": CALDERA_API_KEY,
    "Content-Type": "application/json"
}

# --- Severity mapping by tactic ---
SEVERITY_MAP = {
    "credential-access": "critical",
    "impact": "critical",
    "lateral-movement": "high",
    "privilege-escalation": "high",
    "defense-evasion": "high",
    "execution": "high",
    "persistence": "high",
    "exfiltration": "high",
    "command-and-control": "high",
    "discovery": "medium",
    "collection": "medium",
    "initial-access": "medium",
}

# --- Bank relevance by tactic ---
BANK_RELEVANCE_MAP = {
    "credential-access": "sehr_hoch",
    "impact": "sehr_hoch",
    "lateral-movement": "sehr_hoch",
    "exfiltration": "sehr_hoch",
    "privilege-escalation": "hoch",
    "defense-evasion": "hoch",
    "execution": "hoch",
    "persistence": "hoch",
    "command-and-control": "hoch",
    "collection": "hoch",
    "discovery": "mittel",
    "initial-access": "mittel",
}

# --- SIEM UseCase ID ranges by tactic ---
USECASE_RANGES = OrderedDict([
    ("credential-access",    (1, 19,   "Credential Access Detection")),
    ("privilege-escalation", (20, 29,  "Privilege Escalation Detection")),
    ("lateral-movement",     (30, 39,  "Lateral Movement Detection")),
    ("defense-evasion",      (40, 59,  "Defense Evasion Detection")),
    ("discovery",            (60, 79,  "Discovery and Reconnaissance Detection")),
    ("execution",            (80, 89,  "Suspicious Execution Detection")),
    ("persistence",          (90, 99,  "Persistence Mechanism Detection")),
    ("exfiltration",         (100, 109, "Data Exfiltration Detection")),
    ("collection",           (110, 119, "Data Collection Detection")),
    ("command-and-control",  (120, 129, "C2 Communication Detection")),
    ("impact",               (130, 139, "System Impact Detection")),
    ("initial-access",       (140, 149, "Initial Access Detection")),
])

# --- TIBER phase mapping ---
TIBER_PHASE_MAP = {
    "credential-access": "Active-Phase",
    "impact": "Active-Phase",
    "lateral-movement": "Active-Phase",
    "privilege-escalation": "Active-Phase",
    "defense-evasion": "Active-Phase",
    "execution": "Active-Phase",
    "persistence": "Active-Phase",
    "exfiltration": "Active-Phase",
    "collection": "Active-Phase",
    "command-and-control": "Active-Phase",
    "discovery": "Recon-Phase",
    "initial-access": "Initial-Compromise",
}

# --- German descriptions by technique pattern ---
GERMAN_DESCRIPTIONS = {
    "T1003": "Erkennung von OS Credential Dumping (LSASS, SAM, NTDS, DCSync)",
    "T1003.001": "LSASS Prozess-Memory-Dump via Procdump oder Mimikatz",
    "T1003.002": "Security Account Manager (SAM) Credential Extraktion",
    "T1003.003": "Active Directory NTDS.dit Extraktion via Shadow Copy",
    "T1003.004": "LSA Secrets Extraktion",
    "T1003.005": "Cached Domain Credentials Extraktion",
    "T1003.006": "DCSync Angriff via Directory Replication",
    "T1003.007": "Credential Dump aus /proc Dateisystem",
    "T1003.008": "/etc/passwd und /etc/shadow Extraktion",
    "T1005": "Zugriff auf sensible lokale Dateien und Daten",
    "T1007": "System Service Discovery",
    "T1010": "Anwendungsfenster-Enumeration",
    "T1012": "Windows Registry Abfrage",
    "T1016": "Netzwerkkonfigurations-Enumeration",
    "T1018": "Erkennung von Remote-System-Discovery und Host-Scanning",
    "T1020": "Automatisierte Datenexfiltration",
    "T1021": "Nutzung von Remote-Services fuer Lateral Movement",
    "T1021.001": "RDP-basiertes Lateral Movement",
    "T1021.002": "SMB/Windows Admin Shares Lateral Movement",
    "T1021.003": "DCOM-basiertes Lateral Movement",
    "T1021.004": "SSH-basiertes Lateral Movement",
    "T1021.006": "WinRM-basiertes Lateral Movement",
    "T1027": "Verschleierte Dateien oder Informationen",
    "T1029": "Geplante automatische Datenuebertragung",
    "T1030": "Aufgeteilte Datenexfiltration in kleinen Stuecken",
    "T1033": "System Owner/User Discovery",
    "T1036": "Tarnung als legitimer Prozess oder Datei (Masquerading)",
    "T1037": "Boot oder Logon Initialization Scripts",
    "T1039": "Daten von Network Shared Drive",
    "T1040": "Netzwerk-Traffic-Sniffing fuer Credential-Theft",
    "T1041": "Datenexfiltration ueber C2-Kanal",
    "T1046": "Netzwerk-Service-Scanning",
    "T1047": "Windows Management Instrumentation Ausfuehrung",
    "T1048": "Exfiltration ueber alternativen Protokollkanal",
    "T1049": "System-Netzwerkverbindungen auflisten",
    "T1053": "Persistenz via geplante Aufgaben (Scheduled Task/Job)",
    "T1055": "Code-Injection in laufende Prozesse",
    "T1056": "Input Capture - Tastatureingaben abfangen",
    "T1057": "Prozess-Auflistung und -Discovery",
    "T1059": "Ausfuehrung von Befehlen und Scripts",
    "T1059.001": "PowerShell-basierte Ausfuehrung",
    "T1059.003": "Windows Command Shell Ausfuehrung",
    "T1059.005": "VBScript Ausfuehrung",
    "T1059.006": "Python-basierte Ausfuehrung",
    "T1069": "Berechtigungsgruppen-Discovery",
    "T1070": "Loeschung von Indikatoren und Spuren",
    "T1070.001": "Loeschung von Windows Event Logs",
    "T1070.003": "Loeschung der Befehlshistorie",
    "T1070.004": "Loeschung von Artefakten und Dateien",
    "T1071": "C2-Kommunikation ueber Anwendungsprotokolle",
    "T1071.001": "HTTP/HTTPS-basierte C2-Kommunikation",
    "T1071.004": "DNS-basierte C2-Kommunikation",
    "T1074": "Daten-Staging vor Exfiltration",
    "T1074.001": "Lokales Sammeln von Daten in Staging-Verzeichnissen",
    "T1078": "Verwendung valider Accounts",
    "T1082": "System-Informationssammlung",
    "T1083": "Dateisystem-Enumeration",
    "T1087": "Benutzerkonten-Enumeration",
    "T1087.001": "Lokale Konten-Enumeration",
    "T1087.002": "Domain-Konten-Enumeration",
    "T1095": "Non-Application Layer Protocol C2",
    "T1098": "Account Manipulation",
    "T1102": "Web Service C2-Kommunikation",
    "T1104": "Multi-Stage C2-Channels",
    "T1105": "Download von Tools auf Zielsystem (Ingress Tool Transfer)",
    "T1106": "Native API Ausfuehrung",
    "T1110": "Brute-Force Angriff auf Zugangsdaten",
    "T1112": "Windows Registry Modifikation",
    "T1113": "Bildschirmaufnahme / Screen Capture",
    "T1115": "Clipboard-Daten abgreifen",
    "T1119": "Automatisierte Datensammlung",
    "T1123": "Audio Capture",
    "T1132": "Data Encoding fuer C2",
    "T1134": "Token-Manipulation fuer erhoehte Rechte",
    "T1135": "Netzwerk Share Discovery",
    "T1136": "Erstellung neuer Benutzerkonten",
    "T1140": "Deobfuskation/Dekodierung von Dateien",
    "T1176": "Browser Extensions",
    "T1185": "Browser Session Hijacking",
    "T1187": "Forced Authentication (NTLM)",
    "T1189": "Drive-by Compromise",
    "T1190": "Exploit Public-Facing Application",
    "T1195": "Supply Chain Compromise",
    "T1197": "BITS Jobs Persistenz/Transfer",
    "T1199": "Trusted Relationship",
    "T1201": "Password Policy Discovery",
    "T1202": "Indirect Command Execution",
    "T1204": "User Execution",
    "T1210": "Exploitation of Remote Services",
    "T1217": "Browser Information Discovery",
    "T1218": "System Binary Proxy Execution",
    "T1219": "Remote Access Software",
    "T1220": "XSL Script Processing",
    "T1482": "Domain Trust Enumeration",
    "T1484": "Group Policy Modification",
    "T1485": "Data Destruction",
    "T1486": "Ransomware-Verschluesselung (Data Encrypted for Impact)",
    "T1489": "Stoppen kritischer Dienste (Service Stop)",
    "T1490": "Inhibit System Recovery",
    "T1491": "Defacement / Hinterlassen von Ransomware-Nachrichten",
    "T1496": "Crypto-Mining auf Bankinfrastruktur (Resource Hijacking)",
    "T1497": "Sandbox-Erkennung und Umgehung",
    "T1499": "System-Shutdown oder Endpoint DoS",
    "T1518": "Software Discovery",
    "T1528": "Steal Application Access Token",
    "T1529": "System Shutdown/Reboot",
    "T1537": "Exfiltration zu Cloud-Accounts",
    "T1543": "System-Service-Erstellung und -Manipulation",
    "T1543.003": "Erstellung schadhafter Windows-Services",
    "T1546": "Event Triggered Execution",
    "T1547": "Boot/Logon Autostart Execution",
    "T1548": "UAC-Bypass und Rechteeskalation",
    "T1548.002": "User Account Control Umgehung",
    "T1550": "Use Alternate Authentication Material",
    "T1552": "Ungesicherte Credentials in Dateien/Registry",
    "T1552.001": "Credentials in Dateien",
    "T1552.002": "Credentials aus Windows Registry",
    "T1552.003": "Credentials aus Befehlshistorie (Bash History)",
    "T1552.004": "SSH Private Keys und Zertifikate",
    "T1555": "Credentials from Password Stores",
    "T1555.003": "Browser-Credentials Extraktion",
    "T1558": "Kerberos Ticket Manipulation",
    "T1558.003": "Kerberoasting-Angriff",
    "T1560": "Komprimierung gesammelter Daten",
    "T1560.001": "Archivierung mit Standard-Tools (zip, tar, 7z)",
    "T1562": "Deaktivierung von Sicherheitsmechanismen",
    "T1562.001": "Deaktivierung von AV/EDR",
    "T1563": "Remote Service Session Hijacking",
    "T1565": "Manipulation von Geschaeftsdaten",
    "T1565.001": "Manipulation gespeicherter Daten",
    "T1567": "Exfiltration ueber Webdienste",
    "T1567.002": "Exfiltration zu Cloud Storage",
    "T1569": "Ausfuehrung via System-Services",
    "T1569.002": "Ausfuehrung via Service-Erstellung",
    "T1570": "Lateral Tool Transfer",
    "T1571": "Non-Standard Port C2",
    "T1572": "Protocol Tunneling",
    "T1574": "DLL Hijacking und Execution Flow Manipulation",
    "T1574.010": "Schwache Service-Binary-Berechtigungen",
    "T1615": "Group Policy Discovery",
    "T1622": "Debugger Evasion",
    "T1657": "Direkter Finanzdiebstahl und Transaktionsbetrug",
}


def fetch_abilities() -> List[dict]:
    """Fetch all abilities from Caldera API."""
    print("[*] Fetching all abilities from Caldera API...")
    try:
        resp = requests.get(f"{CALDERA_API}/abilities", headers=HEADERS, verify=False, timeout=30)
        resp.raise_for_status()
        abilities = resp.json()
        print(f"[+] Fetched {len(abilities)} abilities")
        return abilities
    except Exception as e:
        print(f"[!] Error fetching abilities: {e}")
        sys.exit(1)


def normalize_tactic(tactic: str) -> str:
    """Normalize tactic name."""
    tactic_map = {
        "credential-dumping": "credential-access",
        "os-credential-dumping": "credential-access",
        "defensive-evasion": "defense-evasion",
        "hijack-execution-flow---dll-search-order-hijacking": "defense-evasion",
        "discovery/execution": "discovery",
        "commmand-and-control": "command-and-control",
    }
    tactic = tactic.lower().strip()
    return tactic_map.get(tactic, tactic)


def get_description_de(technique_id: str, technique_name: str) -> str:
    """Get German description, falling back to generic."""
    if technique_id in GERMAN_DESCRIPTIONS:
        return GERMAN_DESCRIPTIONS[technique_id]
    # Try parent technique
    parent = technique_id.split(".")[0]
    if parent in GERMAN_DESCRIPTIONS:
        return GERMAN_DESCRIPTIONS[parent] + f" - {technique_name}"
    return f"Erkennung von {technique_name}"


def assign_usecase_ids(techniques_by_tactic: Dict[str, List[Tuple[str, str]]]) -> Dict[str, Tuple[str, str]]:
    """Assign UC-BANK-XXX IDs to technique groups."""
    technique_to_usecase = {}

    for tactic, (start, end, base_name) in USECASE_RANGES.items():
        techniques = techniques_by_tactic.get(tactic, [])
        if not techniques:
            continue

        # Sort techniques
        techniques.sort(key=lambda x: x[0])

        # Group sub-techniques with parent
        parent_groups = defaultdict(list)
        for tid, tname in techniques:
            parent = tid.split(".")[0]
            parent_groups[parent].append((tid, tname))

        # Assign IDs
        current_id = start
        for parent_tid in sorted(parent_groups.keys()):
            if current_id > end:
                # Overflow - reuse last ID
                current_id = end

            usecase_id = f"UC-BANK-{current_id:03d}"

            # Determine usecase name based on parent technique
            group_techniques = parent_groups[parent_tid]
            if len(group_techniques) == 1:
                usecase_name = f"{base_name} - {group_techniques[0][1]}"
            else:
                usecase_name = f"{base_name} - {group_techniques[0][1]}"

            # Truncate long names
            if len(usecase_name) > 80:
                usecase_name = usecase_name[:77] + "..."

            for tid, tname in group_techniques:
                technique_to_usecase[tid] = (usecase_id, usecase_name)

            current_id += 1

    return technique_to_usecase


def generate_lookup(abilities: List[dict]):
    """Generate the MITRE lookup CSV."""
    # Collect unique techniques by tactic
    techniques_by_tactic = defaultdict(list)
    technique_info = {}  # tid -> (tname, tactic)
    skip_tactics = {"unknown", "x", "build-capabilities", "stage-capabilities",
                    "technical-information-gathering", "multiple"}

    for a in abilities:
        tactic = normalize_tactic(a.get("tactic", "unknown"))
        if tactic in skip_tactics:
            continue
        tid = a.get("technique_id", "").strip()
        tname = a.get("technique_name", "").strip()
        if not tid or tid == "unknown":
            continue

        key = (tid, tname)
        if tid not in technique_info:
            technique_info[tid] = (tname, tactic)
            techniques_by_tactic[tactic].append((tid, tname))

    print(f"[*] Found {len(technique_info)} unique techniques across {len(techniques_by_tactic)} tactics")

    # Assign use case IDs
    technique_to_usecase = assign_usecase_ids(techniques_by_tactic)

    # Generate CSV rows
    rows = []
    for tid in sorted(technique_info.keys()):
        tname, tactic = technique_info[tid]
        severity = SEVERITY_MAP.get(tactic, "medium")
        bank_relevance = BANK_RELEVANCE_MAP.get(tactic, "mittel")
        tiber_phase = TIBER_PHASE_MAP.get(tactic, "Active-Phase")
        description_de = get_description_de(tid, tname)

        usecase_id, usecase_name = technique_to_usecase.get(tid, ("UC-BANK-999", "Unclassified Detection"))

        rows.append({
            "technique_id": tid,
            "technique_name": tname,
            "tactic": tactic,
            "severity": severity,
            "bank_relevance": bank_relevance,
            "siem_usecase_id": usecase_id,
            "siem_usecase_name": usecase_name,
            "dora_article": "Art.25",
            "tiber_phase": tiber_phase,
            "description_de": description_de
        })

    # Sort rows by usecase_id then technique_id
    rows.sort(key=lambda r: (r["siem_usecase_id"], r["technique_id"]))

    return rows


def write_csv(rows: List[dict]):
    """Write the lookup CSV."""
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

    fieldnames = ["technique_id", "technique_name", "tactic", "severity", "bank_relevance",
                  "siem_usecase_id", "siem_usecase_name", "dora_article", "tiber_phase", "description_de"]

    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Wrote {len(rows)} rows to {OUTPUT_CSV}")

    # Copy to repo
    os.makedirs(REPO_LOOKUP_DIR, exist_ok=True)
    repo_path = os.path.join(REPO_LOOKUP_DIR, "mitre_attack_bank_mapping.csv")
    shutil.copy2(OUTPUT_CSV, repo_path)
    print(f"[+] Copied to {repo_path}")


def deploy_to_splunk():
    """Deploy lookup to Splunk via REST API."""
    print("[*] Deploying lookup to Splunk...")
    try:
        # Upload via Splunk REST API
        url = f"https://{SPLUNK_HOST}:8089/servicesNS/admin/search/data/lookup-table-files/mitre_attack_bank_mapping.csv"
        with open(OUTPUT_CSV, "rb") as f:
            resp = requests.post(
                url,
                auth=(SPLUNK_USER, SPLUNK_PASS),
                files={"datafile": ("mitre_attack_bank_mapping.csv", f, "text/csv")},
                verify=False,
                timeout=30
            )
        if resp.status_code in [200, 201, 409]:
            print(f"[+] Lookup deployed to Splunk (HTTP {resp.status_code})")
        else:
            # Try creating the lookup first
            create_url = f"https://{SPLUNK_HOST}:8089/servicesNS/admin/search/data/lookup-table-files"
            with open(OUTPUT_CSV, "rb") as f:
                resp2 = requests.post(
                    create_url,
                    auth=(SPLUNK_USER, SPLUNK_PASS),
                    data={"name": "mitre_attack_bank_mapping.csv", "output_mode": "json"},
                    files={"datafile": ("mitre_attack_bank_mapping.csv", f, "text/csv")},
                    verify=False,
                    timeout=30
                )
            if resp2.status_code in [200, 201]:
                print(f"[+] Lookup created on Splunk (HTTP {resp2.status_code})")
            else:
                print(f"[!] Splunk deploy issue: HTTP {resp.status_code} / {resp2.status_code}")
                print(f"    Trying SCP fallback...")
                _scp_fallback()
    except Exception as e:
        print(f"[!] Splunk REST API error: {e}")
        print(f"    Trying SCP fallback...")
        _scp_fallback()


def _scp_fallback():
    """Try to copy file via SCP if REST API fails."""
    try:
        splunk_lookup_dir = "/opt/splunk/etc/apps/search/lookups"
        result = subprocess.run(
            ["scp", "-o", "StrictHostKeyChecking=no", OUTPUT_CSV,
             f"root@{SPLUNK_HOST}:{splunk_lookup_dir}/mitre_attack_bank_mapping.csv"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print(f"[+] Lookup copied via SCP to {SPLUNK_HOST}")
        else:
            print(f"[!] SCP failed: {result.stderr[:200]}")
            print(f"    Manual deployment required: copy {OUTPUT_CSV} to Splunk lookups directory")
    except Exception as e:
        print(f"[!] SCP error: {e}")
        print(f"    Manual deployment required: copy {OUTPUT_CSV} to Splunk lookups directory")


def main():
    print("=" * 70)
    print("  MITRE ATT&CK Bank Lookup Generator")
    print("  Generates comprehensive technique-to-usecase mapping")
    print("=" * 70)
    print()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    abilities = fetch_abilities()
    rows = generate_lookup(abilities)
    write_csv(rows)
    deploy_to_splunk()

    # Summary
    print()
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    usecase_ids = set(r["siem_usecase_id"] for r in rows)
    tactics = set(r["tactic"] for r in rows)
    print(f"  Total technique entries: {len(rows)}")
    print(f"  Unique SIEM use case IDs: {len(usecase_ids)}")
    print(f"  Tactics covered: {len(tactics)}")
    print()
    for tactic in sorted(tactics):
        tactic_rows = [r for r in rows if r["tactic"] == tactic]
        tactic_usecases = set(r["siem_usecase_id"] for r in tactic_rows)
        print(f"  {tactic}: {len(tactic_rows)} techniques, {len(tactic_usecases)} use cases")
    print(f"\n  Output: {OUTPUT_CSV}")
    print("=" * 70)


if __name__ == "__main__":
    main()
