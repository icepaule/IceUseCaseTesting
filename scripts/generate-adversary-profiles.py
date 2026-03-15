#!/usr/bin/env python3
"""
generate-adversary-profiles.py
Queries Caldera API for all available abilities, groups them by MITRE technique/tactic,
and generates adversary profiles organized by banking attack scenarios using REAL abilities.
Outputs YAML files and loads them via Caldera API.
"""
import json
import os
import re
import shutil
import sys
import uuid
import requests
import yaml
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# --- Configuration ---
CALDERA_API = os.environ.get("CALDERA_API", "http://localhost:8888/api/v2")
CALDERA_API_KEY = os.environ.get("CALDERA_API_KEY", "<API_KEY>")
ADVERSARY_DIR = "/opt/caldera/data/adversaries"
REPO_ADVERSARY_DIR = "/root/IceUseCaseTesting/caldera/adversaries"

# Headers for Caldera API
HEADERS = {
    "KEY": CALDERA_API_KEY,
    "Content-Type": "application/json"
}

# --- Tool keyword rankings: abilities mentioning these get priority ---
TOOL_KEYWORDS = {
    "credential-access": [
        "mimikatz", "procdump", "lsass", "ntds", "dcsync", "kerberoast", "rubeus",
        "lazagne", "secretsdump", "wce", "credential", "sekurlsa", "sam", "hashdump",
        "invoke-mimikatz", "powerkatz", "shadow", "passwd", "password", "mimipenguin",
        "npspy", "keymgr"
    ],
    "discovery": [
        "bloodhound", "sharphound", "sharpview", "powerview", "adidnsdump",
        "nltest", "dsquery", "net user", "net group", "whoami", "systeminfo",
        "ipconfig", "arp", "netstat", "nslookup", "tasklist", "nmap", "ping",
        "hostname", "domain", "enum", "recon"
    ],
    "lateral-movement": [
        "psexec", "wmi", "winrm", "rdp", "smb", "dcom", "pass-the-hash",
        "pass-the-ticket", "invoke-command", "net use", "scp", "ssh",
        "smbclient", "mount", "remote"
    ],
    "defense-evasion": [
        "inject", "hollowing", "amsi", "bypass", "timestomp", "masquerad",
        "uac", "defender", "disable", "wevtutil", "clear-eventlog", "dll",
        "process injection", "obfuscat", "encoded", "rundll32", "mavinject"
    ],
    "persistence": [
        "schtask", "scheduled task", "registry", "run key", "service", "dll hijack",
        "com hijack", "startup", "wmi subscription", "crontab", "cron",
        "useradd", "adduser", "net user", "reg add"
    ],
    "execution": [
        "powershell", "wmi", "mshta", "rundll32", "regsvr32", "certutil",
        "bitsadmin", "cscript", "wscript", "cmd", "invoke-expression",
        "iex", "downloadstring", "start-process"
    ],
    "exfiltration": [
        "exfil", "upload", "ftp", "curl", "compress", "archive", "zip", "tar",
        "7z", "rar", "staging", "transfer", "dropbox", "s3", "github", "cloud"
    ],
    "impact": [
        "encrypt", "ransom", "shutdown", "stop-service", "vssadmin", "bcdedit",
        "wbadmin", "delete shadow", "defac", "kill", "rm -rf", "format",
        "resource hijack", "mining", "xmrig"
    ],
    "collection": [
        "screen", "capture", "clipboard", "keylog", "email", "data from",
        "local system", "network share", "find", "stage", "compress",
        "record", "audio"
    ],
    "command-and-control": [
        "dns", "tunnel", "http", "https", "encoding", "proxy", "beacon",
        "reverse shell", "certutil", "bitsadmin", "invoke-webrequest",
        "download", "ingress", "tool transfer"
    ]
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


def has_executor(ability: dict, platforms: list = None) -> bool:
    """Check if ability has a usable executor."""
    if platforms is None:
        platforms = ["windows/psh", "windows/cmd", "linux/sh", "windows/pwsh", "darwin/sh"]
    for executor in ability.get("executors", []):
        plat = f"{executor.get('platform', '')}/{executor.get('name', '')}"
        if plat in platforms and executor.get("command"):
            return True
    return False


def score_ability(ability: dict, tactic_keywords: list) -> int:
    """Score an ability based on how well it matches tool keywords."""
    score = 0
    name_lower = ability.get("name", "").lower()
    desc_lower = ability.get("description", "").lower()

    # Check executor commands
    cmd_text = ""
    for executor in ability.get("executors", []):
        cmd = str(executor.get("command", "")).lower()
        cmd_text += " " + cmd

    all_text = f"{name_lower} {desc_lower} {cmd_text}"

    for keyword in tactic_keywords:
        if keyword.lower() in all_text:
            score += 10

    # Prefer windows executors for banking scenarios
    for executor in ability.get("executors", []):
        plat = f"{executor.get('platform', '')}/{executor.get('name', '')}"
        if plat in ["windows/psh", "windows/cmd"]:
            score += 5
        if plat in ["linux/sh"]:
            score += 2

    # Prefer abilities from stockpile/atomic
    plugin = ability.get("plugin", "")
    if plugin in ["stockpile", "atomic"]:
        score += 3

    return score


def group_abilities_by_tactic(abilities: List[dict]) -> Dict[str, List[dict]]:
    """Group abilities by normalized tactic."""
    by_tactic = defaultdict(list)
    # Normalize tactic names
    tactic_map = {
        "credential-dumping": "credential-access",
        "os-credential-dumping": "credential-access",
        "defensive-evasion": "defense-evasion",
        "hijack-execution-flow---dll-search-order-hijacking": "defense-evasion",
        "discovery/execution": "discovery",
        "commmand-and-control": "command-and-control",
    }
    for a in abilities:
        if not has_executor(a):
            continue
        tactic = a.get("tactic", "unknown").lower().strip()
        tactic = tactic_map.get(tactic, tactic)
        if tactic in ["unknown", "x", "build-capabilities", "stage-capabilities",
                       "technical-information-gathering", "multiple"]:
            # For "multiple", try to assign based on technique
            if tactic == "multiple":
                # Add to relevant tactic based on technique_id pattern
                tid = a.get("technique_id", "")
                # Just add to discovery as catch-all for multi-tactic
                by_tactic["discovery"].append(a)
            continue
        by_tactic[tactic].append(a)
    return by_tactic


def select_best_abilities(abilities: List[dict], tactic: str, max_count: int = 30,
                          technique_filter: list = None, keyword_boost: list = None) -> List[str]:
    """Select best abilities for a profile, preferring real tool usage."""
    keywords = TOOL_KEYWORDS.get(tactic, [])
    if keyword_boost:
        keywords = keyword_boost + keywords

    scored = []
    seen_techniques = set()

    for a in abilities:
        aid = a.get("ability_id", "")
        tid = a.get("technique_id", "")

        # Apply technique filter if specified
        if technique_filter:
            if not any(tid.startswith(tf) for tf in technique_filter):
                continue

        s = score_ability(a, keywords)
        scored.append((s, aid, tid, a.get("name", ""), a))

    # Sort by score descending
    scored.sort(key=lambda x: -x[0])

    selected = []
    for s, aid, tid, name, ability in scored:
        # Ensure technique diversity - at most 3 abilities per technique
        technique_count = sum(1 for _, _, t, _, _ in [(0, x, seen_techniques, "", None) for x in []] if False)
        tid_base = tid.split(".")[0] if "." in tid else tid

        # Count existing abilities for this technique
        existing_for_technique = sum(1 for sel_aid in selected
                                     for sa in abilities
                                     if sa.get("ability_id") == sel_aid and
                                     sa.get("technique_id", "").startswith(tid_base))
        if existing_for_technique >= 3 and len(selected) > 10:
            continue

        selected.append(aid)
        if len(selected) >= max_count:
            break

    return selected


def define_profiles(by_tactic: Dict[str, List[dict]]) -> List[dict]:
    """Define the 10 banking adversary profiles."""
    profiles = []

    # a) bank-credential-access.yml
    cred_abilities = by_tactic.get("credential-access", [])
    cred_ids = select_best_abilities(cred_abilities, "credential-access", max_count=30,
                                     keyword_boost=["mimikatz", "procdump", "lsass", "ntds",
                                                    "dcsync", "kerberoast", "rubeus", "lazagne",
                                                    "sam", "registry", "credential", "password",
                                                    "shadow", "npspy", "secretsdump"])
    profiles.append({
        "id": "b4nk-cr3d-0010-aaaa-000000000010",
        "name": "Bank-Credential-Access-Advanced",
        "filename": "bank-credential-access.yml",
        "description": (
            "Comprehensive credential access simulation for banking environment.\n"
            "Covers: Mimikatz, Procdump/LSASS, NTDS.dit, DCSync, Kerberoasting,\n"
            "SAM dump, LaZagne, credential registry, browser credentials, private keys.\n"
            "MITRE ATT&CK: T1003, T1040, T1110, T1528, T1552, T1555, T1558.\n"
            "DORA Art.25/26 - TIBER-EU Active Phase."
        ),
        "ability_ids": cred_ids
    })

    # b) bank-discovery-recon.yml
    disc_abilities = by_tactic.get("discovery", [])
    disc_ids = select_best_abilities(disc_abilities, "discovery", max_count=30,
                                     keyword_boost=["bloodhound", "sharphound", "powerview",
                                                    "adidnsdump", "nltest", "dsquery",
                                                    "net user", "net group", "whoami",
                                                    "systeminfo", "arp", "netstat"])
    profiles.append({
        "id": "b4nk-d1sc-0020-bbbb-000000000020",
        "name": "Bank-Discovery-Recon-Advanced",
        "filename": "bank-discovery-recon.yml",
        "description": (
            "Comprehensive discovery and reconnaissance simulation for banking.\n"
            "Covers: BloodHound/SharpHound, system enumeration, AD discovery,\n"
            "network scanning, process discovery, domain trust discovery.\n"
            "MITRE ATT&CK: T1010-T1518. DORA Art.25 - TIBER-EU Recon Phase."
        ),
        "ability_ids": disc_ids
    })

    # c) bank-lateral-movement-advanced.yml
    lat_abilities = by_tactic.get("lateral-movement", [])
    lat_ids = select_best_abilities(lat_abilities, "lateral-movement", max_count=25,
                                    keyword_boost=["psexec", "wmi", "winrm", "rdp", "smb",
                                                   "dcom", "pass-the-hash", "pass-the-ticket",
                                                   "invoke-command", "net use", "scp"])
    profiles.append({
        "id": "b4nk-l4t2-0030-cccc-000000000030",
        "name": "Bank-Lateral-Movement-Advanced",
        "filename": "bank-lateral-movement-advanced.yml",
        "description": (
            "Advanced lateral movement simulation for banking networks.\n"
            "Covers: PsExec, WMI, WinRM, RDP, SMB, DCOM, Pass-the-Hash,\n"
            "Pass-the-Ticket, remote file copy, remote service creation.\n"
            "MITRE ATT&CK: T1021, T1550, T1563, T1570. DORA Art.25 - Tests network segmentation."
        ),
        "ability_ids": lat_ids
    })

    # d) bank-defense-evasion-advanced.yml
    evasion_abilities = by_tactic.get("defense-evasion", [])
    evasion_ids = select_best_abilities(evasion_abilities, "defense-evasion", max_count=30,
                                        keyword_boost=["inject", "hollowing", "dll injection",
                                                       "amsi", "bypass", "uac", "log", "clear",
                                                       "timestomp", "masquerad", "defender",
                                                       "disable", "wevtutil"])
    profiles.append({
        "id": "b4nk-3v4s-0040-dddd-000000000040",
        "name": "Bank-Defense-Evasion-Advanced",
        "filename": "bank-defense-evasion-advanced.yml",
        "description": (
            "Advanced defense evasion simulation for banking SOC testing.\n"
            "Covers: Process injection (hollowing, DLL), AMSI bypass, log clearing,\n"
            "timestomping, masquerading, UAC bypass, AV/EDR disabling.\n"
            "MITRE ATT&CK: T1014-T1562. DORA Art.25 - Tests SOC detection capabilities."
        ),
        "ability_ids": evasion_ids
    })

    # e) bank-persistence-advanced.yml
    persist_abilities = by_tactic.get("persistence", [])
    persist_ids = select_best_abilities(persist_abilities, "persistence", max_count=25,
                                        keyword_boost=["schtask", "registry", "run key",
                                                       "service", "dll hijack", "com hijack",
                                                       "startup", "wmi subscription",
                                                       "crontab", "cron"])
    profiles.append({
        "id": "b4nk-p3rs-0050-eeee-000000000050",
        "name": "Bank-Persistence-Advanced",
        "filename": "bank-persistence-advanced.yml",
        "description": (
            "Advanced persistence simulation for banking APT detection.\n"
            "Covers: Scheduled tasks, registry run keys, services, DLL hijacking,\n"
            "COM hijacking, startup folders, WMI subscriptions, account creation.\n"
            "MITRE ATT&CK: T1037-T1574. DORA Art.25 - Tests long-term compromise detection."
        ),
        "ability_ids": persist_ids
    })

    # f) bank-execution-advanced.yml
    exec_abilities = by_tactic.get("execution", [])
    exec_ids = select_best_abilities(exec_abilities, "execution", max_count=25,
                                     keyword_boost=["powershell", "wmi", "mshta", "rundll32",
                                                    "regsvr32", "certutil", "bitsadmin",
                                                    "cscript", "wscript", "invoke-expression"])
    profiles.append({
        "id": "b4nk-3x3c-0060-ffff-000000000060",
        "name": "Bank-Execution-Advanced",
        "filename": "bank-execution-advanced.yml",
        "description": (
            "Advanced execution technique simulation for banking environments.\n"
            "Covers: PowerShell, WMI, MSHTA, Rundll32, Regsvr32, Certutil,\n"
            "Bitsadmin, scripting interpreters, service execution.\n"
            "MITRE ATT&CK: T1047-T1569. DORA Art.25 - Tests endpoint detection."
        ),
        "ability_ids": exec_ids
    })

    # g) bank-exfiltration-advanced.yml
    exfil_abilities = by_tactic.get("exfiltration", [])
    exfil_ids = select_best_abilities(exfil_abilities, "exfiltration", max_count=20,
                                      keyword_boost=["exfil", "upload", "compress", "archive",
                                                     "transfer", "ftp", "curl", "dropbox",
                                                     "s3", "github", "cloud"])
    profiles.append({
        "id": "b4nk-3xf2-0070-aaaa-000000000070",
        "name": "Bank-Exfiltration-Advanced",
        "filename": "bank-exfiltration-advanced.yml",
        "description": (
            "Advanced exfiltration simulation for banking DLP testing.\n"
            "Covers: Data staged, compressed, exfiltration over C2, alternate protocols,\n"
            "scheduled transfer, cloud storage, web service exfiltration.\n"
            "MITRE ATT&CK: T1020-T1567. DORA Art.25 - Tests DLP controls."
        ),
        "ability_ids": exfil_ids
    })

    # h) bank-impact-advanced.yml
    impact_abilities = by_tactic.get("impact", [])
    impact_ids = select_best_abilities(impact_abilities, "impact", max_count=20,
                                       keyword_boost=["service stop", "inhibit recovery",
                                                      "ransom", "encrypt", "defac", "resource",
                                                      "shutdown", "vssadmin", "bcdedit", "wbadmin"])
    profiles.append({
        "id": "b4nk-1mp4-0080-bbbb-000000000080",
        "name": "Bank-Impact-Advanced",
        "filename": "bank-impact-advanced.yml",
        "description": (
            "Advanced impact simulation for banking business continuity testing.\n"
            "Covers: Service stop, inhibit recovery, ransomware simulation,\n"
            "resource hijacking, defacement, data destruction, system shutdown.\n"
            "MITRE ATT&CK: T1485-T1561. DORA Art.25 - Tests BC/DR capabilities."
        ),
        "ability_ids": impact_ids
    })

    # i) bank-collection-advanced.yml
    coll_abilities = by_tactic.get("collection", [])
    coll_ids = select_best_abilities(coll_abilities, "collection", max_count=25,
                                     keyword_boost=["local system", "network share", "clipboard",
                                                    "keylog", "screen capture", "email",
                                                    "archive", "data from", "find", "stage"])
    profiles.append({
        "id": "b4nk-c0ll-0090-cccc-000000000090",
        "name": "Bank-Collection-Advanced",
        "filename": "bank-collection-advanced.yml",
        "description": (
            "Advanced collection simulation for banking data protection testing.\n"
            "Covers: Data from local system, network shares, clipboard, keylogging,\n"
            "screen capture, email collection, input capture, automated collection.\n"
            "MITRE ATT&CK: T1005-T1560. DORA Art.25 - Tests data access controls."
        ),
        "ability_ids": coll_ids
    })

    # j) bank-command-control.yml
    c2_abilities = by_tactic.get("command-and-control", [])
    c2_ids = select_best_abilities(c2_abilities, "command-and-control", max_count=20,
                                   keyword_boost=["dns", "tunnel", "http", "https", "encoding",
                                                  "proxy", "beacon", "reverse", "certutil",
                                                  "bitsadmin", "download", "ingress"])
    profiles.append({
        "id": "b4nk-c2c2-0100-dddd-000000000100",
        "name": "Bank-Command-Control-Advanced",
        "filename": "bank-command-control.yml",
        "description": (
            "Advanced C2 technique simulation for banking network monitoring.\n"
            "Covers: DNS tunneling, HTTP/HTTPS, encoding, proxy usage,\n"
            "ingress tool transfer, protocol tunneling, remote access tools.\n"
            "MITRE ATT&CK: T1071-T1572. DORA Art.25 - Tests network monitoring/IDS."
        ),
        "ability_ids": c2_ids
    })

    return profiles


def generate_yaml(profile: dict) -> str:
    """Generate Caldera adversary YAML format."""
    data = {
        "id": profile["id"],
        "name": profile["name"],
        "description": profile["description"],
        "atomic_ordering": profile["ability_ids"]
    }
    return "---\n\n" + yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)


def save_and_deploy(profiles: List[dict], all_abilities: List[dict]):
    """Save YAML files and deploy via API."""
    os.makedirs(ADVERSARY_DIR, exist_ok=True)
    os.makedirs(REPO_ADVERSARY_DIR, exist_ok=True)

    # Build ability lookup for summary
    ability_lookup = {a["ability_id"]: a for a in all_abilities}

    for profile in profiles:
        filename = profile["filename"]
        yaml_content = generate_yaml(profile)

        # Save to Caldera data directory
        caldera_path = os.path.join(ADVERSARY_DIR, filename)
        with open(caldera_path, "w") as f:
            f.write(yaml_content)
        print(f"[+] Saved: {caldera_path}")

        # Copy to repo
        repo_path = os.path.join(REPO_ADVERSARY_DIR, filename)
        shutil.copy2(caldera_path, repo_path)
        print(f"[+] Copied: {repo_path}")

        # Load via API
        api_payload = {
            "adversary_id": profile["id"],
            "name": profile["name"],
            "description": profile["description"],
            "atomic_ordering": profile["ability_ids"]
        }

        try:
            # Try PUT first (update), then POST (create)
            resp = requests.put(
                f"{CALDERA_API}/adversaries/{profile['id']}",
                headers=HEADERS,
                json=api_payload,
                verify=False,
                timeout=15
            )
            if resp.status_code not in [200, 201]:
                resp = requests.post(
                    f"{CALDERA_API}/adversaries",
                    headers=HEADERS,
                    json=api_payload,
                    verify=False,
                    timeout=15
                )
            if resp.status_code in [200, 201]:
                print(f"[+] API loaded: {profile['name']}")
            else:
                print(f"[!] API load failed ({resp.status_code}): {profile['name']} - {resp.text[:200]}")
        except Exception as e:
            print(f"[!] API error for {profile['name']}: {e}")

        # Print summary
        print(f"    Abilities: {len(profile['ability_ids'])}")
        techniques = set()
        for aid in profile["ability_ids"]:
            a = ability_lookup.get(aid)
            if a:
                techniques.add(a.get("technique_id", "unknown"))
        print(f"    Techniques covered: {sorted(techniques)}")
        print()


def main():
    print("=" * 70)
    print("  Caldera Bank Adversary Profile Generator")
    print("  Queries real abilities from Caldera API")
    print("=" * 70)
    print()

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Fetch all abilities
    abilities = fetch_abilities()

    # Group by tactic
    by_tactic = group_abilities_by_tactic(abilities)
    print("\n[*] Abilities by tactic (with usable executors):")
    for tactic in sorted(by_tactic.keys()):
        techniques = set(a.get("technique_id") for a in by_tactic[tactic])
        print(f"    {tactic}: {len(by_tactic[tactic])} abilities, {len(techniques)} techniques")
    print()

    # Define and generate profiles
    profiles = define_profiles(by_tactic)

    # Save and deploy
    print("\n[*] Saving and deploying profiles...")
    save_and_deploy(profiles, abilities)

    # Final summary
    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    total_abilities = sum(len(p["ability_ids"]) for p in profiles)
    all_techniques = set()
    ability_lookup = {a["ability_id"]: a for a in abilities}
    for p in profiles:
        for aid in p["ability_ids"]:
            a = ability_lookup.get(aid)
            if a:
                all_techniques.add(a.get("technique_id", ""))
    print(f"  Profiles created: {len(profiles)}")
    print(f"  Total abilities used: {total_abilities}")
    print(f"  Unique techniques covered: {len(all_techniques)}")
    print(f"  Output directories:")
    print(f"    - {ADVERSARY_DIR}")
    print(f"    - {REPO_ADVERSARY_DIR}")
    print()
    for p in profiles:
        print(f"  {p['filename']}: {p['name']} ({len(p['ability_ids'])} abilities)")
    print("=" * 70)


if __name__ == "__main__":
    main()
