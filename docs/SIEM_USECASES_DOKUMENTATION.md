# SIEM Use Case Dokumentation - Mittelstaendische Bank
## TIBER-EU / DORA konformes Purple Team Testing mit Caldera

**Version:** 1.0
**Datum:** 2026-03-13
**Klassifikation:** Vertraulich
**Regulatorischer Rahmen:** DORA (EU 2022/2554), TIBER-EU, MaRisk AT 7.2, BAIT, DSGVO

---

## 1. Uebersicht

Diese Dokumentation beschreibt 15 SIEM Use Cases fuer das Purple Team Testing einer
mittelstaendischen Bank. Die Use Cases basieren auf:

- **MITRE ATT&CK v16** Technique-Mapping
- **TIBER-EU Framework** (ECB, aktualisiert Nov 2025)
- **DORA Art. 25-27** (Threat-Led Penetration Testing)
- **Banking Threat Landscape 2025/2026** (RansomHub, LockBit, Lazarus, Scattered Spider)

### Architektur

```
Caldera (Adversary Emulation)
    |
    |-- 6 Banking-Adversary-Profile
    |       |-- bank-ransomware-chain.yml
    |       |-- bank-apt-espionage.yml
    |       |-- bank-insider-threat.yml
    |       |-- bank-lateral-movement.yml
    |       |-- bank-defense-evasion.yml
    |       |-- bank-data-exfil.yml
    |
    v
publish-to-splunk.sh (Enrichment + HEC)
    |
    v
Splunk (10.10.0.66)
    |-- Index: caldera (Rohdaten)
    |-- Index: siem_summary (Korrelierte Events)
    |-- 15 Saved Searches (SIEM UseCases)
    |-- Lookup: mitre_attack_bank_mapping.csv
    |-- Dashboard: TIBER/DORA Bank Purple Team
```

---

## 2. Adversary-Profile (Caldera)

### 2.1 TIBER-Bank-Ransomware-Chain
- **Bedrohungsmodell:** RansomHub / LockBit / Akira (2024-2026)
- **Kill Chain:** Recon → Credential Access → Defense Evasion → Lateral Movement → Collection → Impact
- **MITRE Techniken:** T1018, T1049, T1087, T1482, T1057, T1003.001, T1552.002, T1070, T1562.001, T1021.002, T1570, T1005, T1074.001, T1560.001, T1491, T1499
- **Bank-Risiko:** Vollstaendige Ransomware-Kompromittierung mit Datenverschluesselung
- **DORA-Relevanz:** Art. 19 (Meldepflicht), Art. 25 (Resilienz-Testing)

### 2.2 TIBER-Bank-APT-Espionage
- **Bedrohungsmodell:** Lazarus Group / APT43 (Nordkorea)
- **Kill Chain:** Anti-Analysis → Deep Discovery → Multi-Vector Credential Theft → Persistence → Collection → Exfiltration
- **MITRE Techniken:** T1497, T1087, T1482, T1018, T1049, T1057, T1003, T1552, T1040, T1053.003, T1005, T1119, T1074.001, T1560.001, T1041
- **Bank-Risiko:** Langfristige stille Kompromittierung, Diebstahl von Finanzdaten und Geschaeftsgeheimnissen
- **DORA-Relevanz:** Art. 26 (TLPT), Art. 11 (IKT-Risikomanagement)

### 2.3 TIBER-Bank-Insider-Threat
- **Bedrohungsmodell:** Boesartiger Insider mit legitimem Zugang
- **Kill Chain:** Interne Aufklaerung → Datensammlung → Staging → Exfiltration
- **MITRE Techniken:** T1087.001, T1083, T1005, T1113, T1115, T1074.001, T1560.001, T1030, T1048.003
- **Bank-Risiko:** Diebstahl von Kundendaten, Kontoinformationen, Transaktionsdaten
- **DORA-Relevanz:** Art. 25 (internes Testing), Art. 13 (Zugangskontrollen)

### 2.4 TIBER-Bank-Lateral-Movement
- **Bedrohungsmodell:** Scattered Spider / Volt Typhoon (Living-off-the-Land)
- **Kill Chain:** Network Recon → Credential Harvest → Privilege Escalation → Multi-Vector Lateral Movement → Service Execution
- **MITRE Techniken:** T1018, T1049, T1016, T1057, T1003.001, T1552.002, T1548.002, T1574.010, T1021.002, T1021.004, T1021.006, T1570, T1569.002
- **Bank-Risiko:** Ueberwindung der Netzwerksegmentierung, Zugriff auf Kernbanksysteme
- **DORA-Relevanz:** Art. 25 (Netzwerksegmentierungs-Test), Art. 9 (Netzwerkschutz)

### 2.5 TIBER-Bank-Defense-Evasion
- **Bedrohungsmodell:** Fortgeschrittener Angreifer mit Anti-Detection-Faehigkeiten
- **Kill Chain:** Sandbox Detection → Security Tool Deaktivierung → Process Injection → Indicator Removal → Execution Obfuscation
- **MITRE Techniken:** T1497, T1562.001, T1057, T1055, T1070, T1059.001
- **Bank-Risiko:** Test der SIEM-Erkennungsfaehigkeit, Umgehung von EDR/AV
- **DORA-Relevanz:** Art. 25 (Erkennungsfaehigkeit), Art. 10 (Erkennung anomaler Aktivitaeten)

### 2.6 TIBER-Bank-Data-Exfiltration
- **Bedrohungsmodell:** Multi-Channel Datendiebstahl
- **Kill Chain:** Data Discovery → Staging → Multi-Channel Exfiltration (C2, FTP, GitHub, Cloud)
- **MITRE Techniken:** T1005, T1119, T1074.001, T1560.001, T1030, T1041, T1048.003, T1567.001, T1029
- **Bank-Risiko:** Massiver Kundendaten-Abfluss, Reputationsschaden, regulatorische Konsequenzen
- **DORA-Relevanz:** Art. 19 (Meldepflicht), Art. 25 (DLP-Testing)

---

## 3. SIEM Use Case Katalog

### UC-BANK-001: Credential Dumping Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1003, T1003.001, T1003.003, T1040, T1552, T1552.002, T1552.003, T1552.004 |
| **Caldera Abilities** | Procdump LSASS, PowerKatz, MiniDumpWriteDump, Registry Credentials, Network Sniffing, SSH Key Discovery |
| **Erkennungslogik** | Matched auf Mimikatz-Muster, Procdump-LSASS-Zugriffe, Registry-Credential-Queries, Netzwerk-Sniffing |
| **Trigger aus** | Index `caldera`, Sourcetype `caldera:command:enriched` |
| **Schreibt nach** | Index `siem_summary`, Sourcetype `siem:usecase:triggered` |
| **Frequenz** | Alle 5 Minuten |
| **Bank-Kontext** | Zugriff auf SWIFT-Credentials, HSM-Keys, Datenbank-Passwoerter |
| **DORA Referenz** | Art. 25 - IKT-Risikomanagement, Art. 26 - TLPT |
| **Regulatorik** | MaRisk AT 7.2, BAIT, EBA Guidelines on ICT Risk |
| **Remediation** | Sofort-Isolierung, Passwort-Reset, Lateral-Movement-Pruefung |
| **False-Positive** | Legitime Admin-Tools (ProcMon), geplante Credential-Rotation |

### UC-BANK-002: Privilege Escalation Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1548, T1548.002, T1134, T1574, T1574.010 |
| **Caldera Abilities** | UAC Bypass Registry, Bypass UAC Medium, DLL Hijack, SUID Exploit, Weak Executables |
| **Erkennungslogik** | UAC-Bypass-Muster (fodhelper, eventvwr, slui), DLL-Hijacking, Token-Manipulation |
| **Bank-Kontext** | Erhoehte Rechte fuer Kernbanksystem-Zugriff, DB-Administratorzugang |
| **DORA Referenz** | Art. 25 |
| **Remediation** | UAC-Haertung, Least-Privilege-Durchsetzung, Application Whitelisting |

### UC-BANK-003: Network Reconnaissance Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH (kumuliert CRITICAL bei >=4 verschiedenen Techniken) |
| **MITRE Techniken** | T1016, T1018, T1049, T1057, T1082, T1083, T1087, T1087.001, T1087.002, T1482 |
| **Caldera Abilities** | ARP Cache, Network Connections, Find Users, Domain Enumeration, GetComputers, Process Discovery |
| **Erkennungslogik** | Kumulations-Erkennung: >=3 Recon-Events ODER >=2 verschiedene Techniken in 10 Minuten |
| **Bank-Kontext** | Kartierung des Banknetzwerks, Identifikation von Kernbanksystemen |
| **DORA Referenz** | Art. 25 |
| **Remediation** | Netzwerksegmentierung pruefen, IDS-Signaturen aktualisieren |

### UC-BANK-004: Lateral Movement Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1021, T1021.002, T1021.004, T1021.006, T1570 |
| **Caldera Abilities** | SMB Copy, Net Use, WinRM Agent, SSH Agent, SCP Transfer, Mount Share |
| **Erkennungslogik** | SMB/WinRM/SSH/PsExec-basierte Bewegung, Tool-Transfer zwischen Hosts |
| **Bank-Kontext** | Ueberwindung DMZ→Kernbank, Zugriff auf Zahlungsverkehrssysteme |
| **DORA Referenz** | Art. 25 (Segmentierungstest), Art. 9 |
| **Remediation** | Netzwerksegmentierung verstaerken, Zero-Trust-Architektur, Jump-Server |

### UC-BANK-005: Suspicious Execution Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **MITRE Techniken** | T1059, T1059.001, T1047, T1569, T1569.002 |
| **Caldera Abilities** | PowerShell Execution, WMI Process, Service Creation, PowerKatz Invoke |
| **Erkennungslogik** | Encoded PowerShell, IEX/DownloadString, WMI-Prozesserstellung, Service-Creation |
| **Bank-Kontext** | Malware-Deployment, Payload-Execution auf Bankservern |
| **DORA Referenz** | Art. 25 |
| **Remediation** | PowerShell Constrained Language Mode, AppLocker/WDAC, Script-Block-Logging |

### UC-BANK-006: Data Exfiltration Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1041, T1048, T1048.003, T1029, T1030, T1567, T1567.001, T1567.002, T1537 |
| **Caldera Abilities** | C2 Exfil, FTP Exfil, GitHub Gist/Repo Exfil, Scheduled Exfil, Chunked Transfer |
| **Erkennungslogik** | Datenupload-Muster, Cloud-Service-Zugriffe, FTP-Transfers, C2-Channel-Exfil |
| **Bank-Kontext** | Kundendaten-Abfluss, DSGVO-Verletzung, Reputationsschaden |
| **Compliance** | DSGVO Art. 33 (72h Meldepflicht), DORA Art. 19 |
| **Remediation** | DLP-Aktivierung, Proxy-Verschaerfung, Cloud-Service-Blocking |

### UC-BANK-007: Defense Evasion Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1562, T1562.001, T1055, T1055.001, T1055.002, T1497, T1497.001, T1497.003 |
| **Caldera Abilities** | Disable Defender, ExecutionPolicy Bypass, Process Injection, Signed Binary Execution, Sandbox Detection |
| **Erkennungslogik** | AV/EDR-Deaktivierung, Process-Injection-Muster, Sandbox-Checks |
| **Bank-Kontext** | Umgehung der Sicherheitsinfrastruktur, Blind Spots im Monitoring |
| **DORA Referenz** | Art. 25 (Erkennungsfaehigkeits-Test) |
| **Remediation** | Tamper Protection aktivieren, EDR-Integritaetsmonitoring |

### UC-BANK-008: Persistence Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **MITRE Techniken** | T1053, T1053.003, T1136, T1543, T1543.003 |
| **Caldera Abilities** | Cron Job Persistence, Service Binary Replace, Account Creation |
| **Erkennungslogik** | Neue Cron-Jobs, neue Services, neue Benutzerkonten |
| **Bank-Kontext** | Langfristiger APT-Zugang, Backdoor in Produktionsumgebung |
| **DORA Referenz** | Art. 25 |
| **Remediation** | Baseline-Monitoring, File-Integrity-Monitoring, Account-Auditing |

### UC-BANK-009: Log Tampering Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1070, T1070.001, T1070.003, T1070.004 |
| **Caldera Abilities** | Clear Event Logs, Clear Command History, Delete Payload, Deadman Agent Delete |
| **Erkennungslogik** | wevtutil cl, Clear-EventLog, history -c, Dateiloeschung in Log-Verzeichnissen |
| **Bank-Kontext** | Compliance-Verstoss, Forensik-Behinderung, Audit-Trail-Verlust |
| **Compliance** | MaRisk AT 7.2 (lueckenlose Protokollierung), DORA Art. 12 |
| **Remediation** | Zentrales Log-Shipping (Write-Once), SIEM-Integritaetsmonitoring |

### UC-BANK-010: Sensitive Data Access Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **MITRE Techniken** | T1005, T1074, T1074.001, T1113, T1115, T1119, T1560, T1560.001 |
| **Caldera Abilities** | File Search, Data Staging, Screen Capture, Clipboard Copy, Archive Collection |
| **Erkennungslogik** | Massenhafte Dateizugriffe, Staging-Verzeichnisse, Archivierung, Screenshots |
| **Bank-Kontext** | Zugriff auf Kontoauszuege, Transaktionslogs, Kundenstammdaten |
| **DORA Referenz** | Art. 25 |
| **Remediation** | Data Classification, DLP, UEBA-Anomalieerkennung |

### UC-BANK-011: C2 Communication Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1071, T1071.001, T1105 |
| **Caldera Abilities** | Ragdoll Agent, PSTools Install, PowerShell Core Install |
| **Erkennungslogik** | Beacon-Muster, Tool-Download-Cradles, Certutil URLCache |
| **Bank-Kontext** | Aktive Fernsteuerung von Bankinfrastruktur |
| **DORA Referenz** | Art. 25 |
| **Remediation** | DNS-Monitoring, SSL-Inspection, Proxy-Analyse, JA3-Fingerprinting |

### UC-BANK-012: Ransomware Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1486, T1489, T1491 |
| **Caldera Abilities** | Leave Ransom Note, Shutdown System, Service Stop |
| **Erkennungslogik** | Verschluesselungsmuster, VSS-Loeschung, Service-Stops, Ransom-Notes |
| **Bank-Kontext** | Betriebsunterbrechung, Zahlungsverkehr-Ausfall, Doppel-Erpressung |
| **Compliance** | DORA Art. 19 (sofortige Meldung), Art. 17 (IKT-Vorfaelle) |
| **Remediation** | Sofort-Isolierung, Backup-Validierung, CSIRT-Aktivierung, BaFin-Meldung |

### UC-BANK-013: Crypto Mining Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **MITRE Techniken** | T1496 |
| **Erkennungslogik** | XMRig-Prozesse, Stratum-Protokoll, Mining-Pool-Verbindungen |
| **Bank-Kontext** | Ressourcenmissbrauch, Performance-Degradation |

### UC-BANK-014: System Impact Detection
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **MITRE Techniken** | T1499, T1565, T1565.001 |
| **Erkennungslogik** | System-Shutdowns, Datenmanipulation, destruktive Befehle |
| **Bank-Kontext** | Business-Continuity-Gefaehrdung, Datenintegritaetsverlust |

### UC-BANK-015: Kill Chain Correlation (Meta-UseCase)
| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Trigger-Bedingung** | >=3 verschiedene Use Cases innerhalb von 30 Minuten auf demselben Host |
| **Erkennungslogik** | Korreliert alle UC-BANK-001 bis UC-BANK-014 Trigger |
| **Korrelations-Muster** | Full Kill Chain (Recon→Creds→LateralMov), Data Breach (Creds→Exfil), Ransomware (Evasion→Ransomware), Insider (DataAccess→Exfil) |
| **Bank-Kontext** | Mehrphasiger koordinierter Angriff auf Bankinfrastruktur |
| **Response** | CSIRT-Aktivierung, Systemisolierung, BaFin/EZB-Meldung vorbereiten |

---

## 4. MITRE ATT&CK Abdeckung

| Taktik | Techniken | Use Cases | Schweregrad |
|--------|-----------|-----------|-------------|
| Discovery | T1016, T1018, T1049, T1057, T1082, T1083, T1087, T1482 | UC-003 | medium-high |
| Credential Access | T1003, T1040, T1552 | UC-001 | critical |
| Privilege Escalation | T1548, T1134, T1574 | UC-002 | critical |
| Defense Evasion | T1055, T1070, T1497, T1562 | UC-007, UC-009 | critical |
| Lateral Movement | T1021, T1570 | UC-004 | critical |
| Execution | T1047, T1059, T1569 | UC-005 | high |
| Persistence | T1053, T1136, T1543 | UC-008 | high |
| Collection | T1005, T1074, T1113, T1115, T1119, T1560 | UC-010 | high |
| Exfiltration | T1029, T1030, T1041, T1048, T1537, T1567 | UC-006 | critical |
| C2 | T1071, T1105 | UC-011 | critical |
| Impact | T1486, T1489, T1491, T1496, T1499, T1565 | UC-012, UC-013, UC-014 | critical |

**Gesamtabdeckung: 63 MITRE Sub-/Techniken ueber 15 SIEM Use Cases**

---

## 5. Splunk-Datenfluss

```
Caldera API (/api/v2/operations)
    |
    v
publish-to-splunk.sh
    |-- Base64-Dekodierung
    |-- MITRE-Enrichment (Lookup)
    |-- Artefakt-Klassifikation
    |-- UseCase-Zuordnung
    |
    v
Splunk HEC (10.10.0.66:8088)
    |
    +-- Index: caldera
    |       Sourcetype: caldera:command:enriched
    |       Sourcetype: caldera:agent
    |       Sourcetype: caldera:operation
    |
    +-- Saved Searches (alle 5 Min)
    |       UC-BANK-001 bis UC-BANK-014
    |
    +-- Index: siem_summary
    |       Sourcetype: siem:usecase:triggered
    |       Sourcetype: siem:usecase:killchain
    |       Sourcetype: siem:caldera:summary
    |
    +-- Dashboard: bank_purple_team
            KPIs, Testcase-Matrix, MITRE-Heatmap,
            Kill-Chain-Timeline, DORA-Compliance,
            Erkennungsluecken-Analyse
```

---

## 6. Betriebsanleitung

### Tests ausfuehren
```bash
# Alle 6 Banking-Profile sequentiell ausfuehren
/opt/caldera-splunk/run-bank-adversaries.sh

# Ergebnisse nach Splunk publizieren
/opt/caldera-splunk/publish-to-splunk.sh
```

### Splunk-App installieren
```bash
export SPLUNK_PASS='admin_passwort'
/opt/caldera-splunk/install-splunk-app.sh
```

### Dashboard aufrufen
```
https://10.10.0.66/app/caldera_bank_siem/bank_purple_team
```

---

## 7. Regulatorische Zuordnung

| Regulierung | Artikel | Abdeckung durch |
|-------------|---------|-----------------|
| DORA | Art. 9 - Netzwerkschutz | UC-004 (Lateral Movement) |
| DORA | Art. 10 - Anomalieerkennung | UC-007 (Defense Evasion), UC-015 (Kill Chain) |
| DORA | Art. 11 - IKT-Risikomanagement | Alle UseCases |
| DORA | Art. 12 - Logging | UC-009 (Log Tampering) |
| DORA | Art. 13 - Zugangskontrollen | UC-001 (Credentials), UC-002 (Priv Esc) |
| DORA | Art. 17 - IKT-Vorfaelle | UC-012 (Ransomware), UC-014 (Impact) |
| DORA | Art. 19 - Meldepflicht | UC-006 (Exfil), UC-012 (Ransomware) |
| DORA | Art. 25 - Resilienz-Testing | Alle UseCases |
| DORA | Art. 26 - TLPT | Alle Adversary-Profile |
| MaRisk | AT 7.2 | UC-009 (Protokollierung) |
| BAIT | Abschnitt 5 | UC-001 bis UC-015 |
| DSGVO | Art. 33 | UC-006 (Datenschutzverletzung) |
| TIBER-EU | Active Phase | Alle Adversary-Profile |

---

## 8. Quellen und Referenzen

- MITRE ATT&CK v16: https://attack.mitre.org/
- MITRE CTID CRI Profile Mapping: https://ctid.mitre.org/blog/2025/06/16/threat-informed-defense-for-the-financial-sector/
- TIBER-EU Framework (2025): https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html
- DORA TLPT RTS (2025): https://tiber.info/blog/2025/06/18/the-dora-threat-led-penetration-testing-rts-has-been-published/
- PT Security Financial Forecast 2025-2026: https://global.ptsecurity.com/en/research/analytics/cyberthreats-to-the-financial-sector--forecast-for-2025-2026/
- Flashpoint Financial Threat Actors: https://flashpoint.io/blog/top-threat-actor-groups-targeting-financial-sector/
- Kaspersky APT Financial Q4/2025: https://ics-cert.kaspersky.com/publications/reports/2026/03/06/apt-and-financial-attacks-on-industrial-organizations-in-q4-2025/
