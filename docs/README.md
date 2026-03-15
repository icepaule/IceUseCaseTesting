# Purple Team Testing Framework - Mittelstaendische Bank

## TIBER-EU / DORA / BaFin-konformes Adversary Emulation Framework

**Version:** 2.0
**Datum:** 2026-03-15
**Klassifikation:** Vertraulich - nur fuer autorisiertes Personal
**Regulatorischer Rahmen:** DORA (EU 2022/2554), TIBER-EU, MaRisk AT 7.2, BAIT, EBA/GL/2019/04

---

## 1. Executive Summary

Dieses Framework implementiert ein vollautomatisiertes Purple Team Testing fuer eine mittelstaendische Bank gemaess den Anforderungen aus:

- **DORA Art. 24-27**: IKT-Resilienztests und Threat-Led Penetration Testing (TLPT)
- **BaFin MaRisk AT 7.2**: Anforderungen an die IT-Sicherheit
- **BAIT Abschnitt 5**: Informationssicherheitsmanagement
- **EZB TIBER-EU**: Threat Intelligence-Based Ethical Red Teaming
- **EBA/GL/2019/04**: Guidelines on ICT and Security Risk Management

### Kernkomponenten

| Komponente | Beschreibung | Standort |
|-----------|-------------|----------|
| MITRE Caldera v5.0 | Adversary Emulation Platform | Caldera-Server |
| Splunk Enterprise | SIEM-Plattform mit Custom App | Splunk-Server |
| 16 Adversary Profile | Banking-spezifische Angriffsszenarien | Caldera |
| 111 SIEM Use Cases | Erkennungsregeln ueber 12 Taktiken | Splunk |
| 188 MITRE Mappings | Technique-to-UseCase Zuordnungen | Lookup CSV |
| Scheduled Runner | 3x taegliche automatische Ausfuehrung | Cron |
| Compliance Alerting | Email-Alerts bei FAILED UseCases | Splunk + Mail |

---

## 2. Architektur

![Systemarchitektur](images/flow_architecture.png)

### Datenfluss

```
Caldera Server
    |-- 16 Bank-Adversary-Profile (227 Abilities)
    |-- Batch Planner -> 4 Agents (Win/Linux)
    |
    v
publish-to-splunk.sh (MITRE ATT&CK Enrichment)
    |
    v
Splunk HEC -> Index: caldera (sourcetype: caldera:command:enriched)
    |
    +-- 113 Saved Searches (5-10 Min Intervall)
    |       |-- 111 Use Case Detektoren
    |       |-- 1 Summary Populator
    |       |-- 1 Kill Chain Correlator
    |
    +-- Index: siem_summary
    |       |-- siem:usecase:triggered
    |       |-- siem:usecase:killchain
    |       |-- siem:usecase:compliance
    |
    +-- Dashboards
    |       |-- bank_purple_team (Hauptuebersicht)
    |       |-- usecase_detail (Drilldown)
    |
    +-- Compliance Alert -> Email bei FAILED
```

### Test-Infrastruktur

| Host | Plattform | IP | Rolle |
|------|-----------|-----|-------|
| DC-Test01 | Windows Server | Test-Netzwerk | Domain Controller |
| WIN11-TEST01 | Windows 11 | Test-Netzwerk | Client-Workstation |
| ubuntu-test-01 | Ubuntu 24.04 | Test-Netzwerk | Linux-Server |
| rhel9-test01 | RHEL 9.7 | Test-Netzwerk | Enterprise Linux |

---

## 3. DORA Compliance-Mapping

![DORA Compliance](images/flow_dora_compliance.png)

### Art. 24 - Allgemeine Anforderungen an IKT-Resilienztests

| Anforderung | Umsetzung | Nachweis |
|------------|-----------|---------|
| Regelmaessige Tests | 3x taegliche automatisierte Ausfuehrung | Cron-Logs, Compliance-Dashboard |
| Risikoorientierter Ansatz | 16 Profile basierend auf Banking Threat Landscape | Adversary-Profile YAML |
| Dokumentation | Automatische ITSO-Reports, Dashboard-Exports | Splunk, GitHub |

### Art. 25 - IKT-Instrumente und -Systeme testen

| Anforderung | Umsetzung | Use Cases |
|------------|-----------|-----------|
| Netzwerksicherheit | Lateral Movement Detection | UC-BANK-030..034 |
| Zugangskontrollen | Credential Access Detection | UC-BANK-001..008 |
| Anomalieerkennung | Defense Evasion + Kill Chain | UC-BANK-040..059, UC-999 |
| Physische Sicherheit | Endpoint-basierte Tests | Agent-Deployment auf allen Plattformen |
| Quellcode-Reviews | Nicht im Scope (separate Massnahme) | - |

### Art. 26 - TLPT (Threat-Led Penetration Testing)

| TLPT-Anforderung | Umsetzung |
|------------------|-----------|
| Threat Intelligence | TIBER-Bank-* Profile basierend auf realen APT-Gruppen |
| Red Team Simulation | Caldera mit 227 realen Abilities (Mimikatz, BloodHound, etc.) |
| Blue Team Validierung | 111 SIEM Use Cases pruefen Erkennung |
| Purple Team Integration | Dashboard zeigt PASSED/FAILED pro UseCase |
| Berichterstattung | ITSO-Report-Template, Compliance-Status JSON |
| Mindestens alle 3 Jahre | Framework erlaubt beliebige Frequenz (Standard: taeglich) |

### Art. 19 - Meldepflicht

| Bedingung | Aktion | Use Case |
|-----------|--------|----------|
| Schwerwiegender IKT-Vorfall | BaFin-Meldung < 4h | UC-BANK-130..139 (Impact) |
| Datenschutzverletzung | DSGVO Art. 33 (72h) | UC-BANK-100..106 (Exfiltration) |
| Kill Chain erkannt | CSIRT-Aktivierung | UC-BANK-999 |

---

## 4. BaFin / MaRisk / BAIT Anforderungen

### MaRisk AT 7.2 - IT-Risikomanagement

| MaRisk-Anforderung | Umsetzung |
|---------------------|-----------|
| Schutzbedarf feststellen | Severity-Klassifikation (critical/high/medium/low) |
| Risiken identifizieren | 188 MITRE Technique Mappings |
| Massnahmen definieren | Remediation-Empfehlungen pro UseCase |
| Wirksamkeit pruefen | Automatische PASSED/FAILED Validierung |
| Protokollierung | Lueckenlose Audit-Trails in Splunk |

### BAIT Abschnitt 5 - Informationssicherheitsmanagement

| BAIT-Anforderung | Umsetzung |
|-------------------|-----------|
| 5.1 Informationssicherheitsleitlinie | Framework-Dokumentation |
| 5.2 Informationsrisikomanagement | 111 SIEM Use Cases mit Risikoklassifikation |
| 5.3 Informationssicherheitsprozesse | Automatisierte 3x/Tag Tests |
| 5.4 Schwachstellenmanagement | Erkennungsluecken-Dashboard |
| 5.5 Penetrationstests | TIBER-konforme Adversary Emulation |

---

## 5. EZB TIBER-EU Compliance

### TIBER-EU Phasenmodell

| Phase | Umsetzung |
|-------|-----------|
| **Preparation** | Framework-Setup, Agent-Deployment, Profile-Definition |
| **Testing - Threat Intelligence** | Banking Threat Landscape 2025/2026 als Basis |
| **Testing - Red Team** | Caldera Adversary Emulation mit realen Tools |
| **Closure** | Compliance-Report, Remediation-Tracking |

### Abgedeckte Bedrohungsakteure

| Profil | Bedrohungsakteur | Kill Chain |
|--------|-----------------|------------|
| TIBER-Bank-Ransomware-Chain | RansomHub/LockBit/Akira | Recon > Creds > Evasion > Lateral > Impact |
| TIBER-Bank-APT-Espionage | Lazarus/APT43 | Anti-Analysis > Discovery > Credential Theft > Exfiltration |
| TIBER-Bank-Insider-Threat | Boesartiger Insider | Discovery > Collection > Staging > Exfiltration |
| TIBER-Bank-Lateral-Movement | Scattered Spider/Volt Typhoon | Recon > Creds > PrivEsc > Lateral Movement |
| TIBER-Bank-Defense-Evasion | Fortgeschrittener APT | Sandbox Detection > AV Disable > Injection > Log Tampering |
| TIBER-Bank-Data-Exfiltration | Multi-Channel Exfil | Data Discovery > Staging > Multi-Channel Exfil |

---

## 6. Testausfuehrung

### Automatisierte Ausfuehrung (3x taeglich)

![Testprozess](images/flow_testprocess.png)

```bash
# Cron installieren
crontab /opt/caldera-splunk/caldera-cron

# Manuelle Ausfuehrung
/opt/caldera-splunk/scheduled-test-runner.sh
```

### Ablauf

1. **Agent-Pruefung**: Verifizierung dass alle Sandcat-Agents aktiv sind
2. **Profil-Ausfuehrung**: Alle 16 Adversary-Profile gegen Gruppe "claude"
3. **Daten-Publikation**: Enriched Events via HEC nach Splunk
4. **SIEM-Validierung**: Splunk Saved Searches pruefen Erkennung
5. **Compliance-Check**: Alle 111 UseCases auf PASSED/FAILED pruefen
6. **Alerting**: Email bei FAILED UseCases

### Manuelle Testschritte

```bash
# Agent-Deployment (Windows)
/opt/caldera-splunk/deploy-windows-agent.sh -t <IP> -u <user> -p <pass>

# Agent-Deployment (Linux)
/opt/caldera-splunk/deploy-linux-agent.sh -t <IP> -u <user> -p <pass>

# Ergebnisse publizieren
/opt/caldera-splunk/publish-to-splunk.sh

# Framework erweitern
/opt/caldera-splunk/deploy-siem-framework.sh all
```

---

## 7. Alert- und Eskalationsprozess

![Eskalationsprozess](images/flow_escalation.png)

### Eskalationsstufen

| Stufe | Bedingung | Reaktionszeit | Aktion |
|-------|-----------|---------------|--------|
| L1 | MEDIUM UseCase triggered | < 4h | SOC L1 Untersuchung |
| L2 | HIGH UseCase triggered | < 1h | SOC L2 Analyse |
| L3 | CRITICAL UseCase triggered | < 15min | Sofort-Triage |
| L4 | Kill Chain (UC-999) | Sofort | CSIRT-Aktivierung, Isolierung |
| L5 | Meldepflichtiger Vorfall | < 4h | BaFin-Meldung, EZB-Bericht |

### Compliance Alerting

- **Empfaenger**: Konfigurierbar (Standard: ITSO-Team)
- **Frequenz**: Stuendliche Pruefung durch Splunk Saved Search
- **Inhalt**: UseCase ID, Name, Schweregrad, DORA-Referenz, letzter Trigger
- **Zusaetzlich**: 3x/Tag durch scheduled-test-runner.sh

---

## 8. Dashboard-Uebersicht

### Haupt-Dashboard (bank_purple_team)

- **KPI-Panels**: Testcases, Artefakte, SIEM-Trigger, Kill Chains, MITRE-Techniken
- **Compliance Status**: Gesamt/PASSED/FAILED/Rate
- **Testcase-Matrix**: Klickbar mit Drilldown zu UseCase-Details
- **MITRE Heatmap**: Taktik-Abdeckung
- **UseCase Status**: PASSED/FAILED mit Farbcodierung
- **Kill Chain Timeline**: Angriffsphasen ueber Zeit
- **DORA Compliance**: Testabdeckung pro Artikel
- **Erkennungsluecken**: Unerkannte Techniken

### Detail-Dashboard (usecase_detail)

- **UseCase Metadaten**: MITRE, DORA, Schweregrad, Beschreibung
- **Compliance Status**: PASSED/FAILED KPI
- **Test-Befehle**: Exakte Caldera-Commands pro Ability
- **Trigger-Events**: SIEM-Trigger mit Kontext
- **Trigger-Verlauf**: 7-Tage-Historie als Timechart
- **Abgleich**: Getestet vs. Erkannt pro Technik

---

## 9. Deployment auf neuen Systemen

### Voraussetzungen

- MITRE Caldera v5.0+ mit Stockpile- und Atomic-Plugins
- Splunk Enterprise 9.x+ mit HEC-Endpoint
- Python 3.8+ auf dem Caldera-Server
- SSH-Zugang zu Ziel-Hosts (Linux) oder WinRM (Windows)

### Schnell-Deployment

```bash
# 1. Repository klonen
git clone https://github.com/icepaule/IceUseCaseTesting.git
cd IceUseCaseTesting

# 2. Konfiguration anpassen
export CALDERA_API_KEY=<API_KEY>
export SPLUNK_HOST=<SPLUNK_IP>
export SPLUNK_PASS=<PASSWORD>

# 3. Framework deployen
./scripts/deploy-siem-framework.sh all

# 4. Agents deployen
./scripts/deploy-linux-agent.sh -t <TARGET_IP> -u <USER> -p <PASS>
./scripts/deploy-windows-agent.sh -t <TARGET_IP> -u <USER> -p <PASS>

# 5. Cron installieren
crontab caldera-cron

# 6. Dashboard aufrufen
# https://<SPLUNK_HOST>:8000/app/caldera_bank_siem/bank_purple_team
```

---

## 10. Quellen und Referenzen

- MITRE ATT&CK v16: https://attack.mitre.org/
- DORA Verordnung (EU) 2022/2554
- DORA TLPT RTS (Delegierte Verordnung)
- TIBER-EU Framework (EZB)
- BaFin MaRisk (aktualisierte Fassung)
- BaFin BAIT (aktualisierte Fassung)
- EBA Guidelines on ICT and Security Risk Management (EBA/GL/2019/04)
- MITRE CTID Financial Sector Profile

---

*Dieses Dokument ist vertraulich und nur fuer autorisiertes Personal bestimmt.*
