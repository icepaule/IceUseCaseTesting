# SIEM Use Case Dokumentation

## Purple Team Testing Framework - Mittelstaendische Bank
## TIBER-EU / DORA / BaFin / EZB-konform

**Version:** 2.0
**Datum:** 2026-03-15
**Klassifikation:** Vertraulich
**Use Cases gesamt:** 111
**MITRE Technique Mappings:** 188
**Taktiken abgedeckt:** 12

---

## Inhaltsverzeichnis

1. [Credential Access](#credential-access) (8 Use Cases)
2. [Privilege Escalation](#privilege-escalation) (5 Use Cases)
3. [Lateral Movement](#lateral-movement) (5 Use Cases)
4. [Defense Evasion](#defense-evasion) (20 Use Cases)
5. [Discovery](#discovery) (20 Use Cases)
6. [Execution](#execution) (8 Use Cases)
7. [Persistence](#persistence) (9 Use Cases)
8. [Exfiltration](#exfiltration) (7 Use Cases)
9. [Collection](#collection) (10 Use Cases)
10. [Command And Control](#command-and-control) (6 Use Cases)
11. [Impact](#impact) (10 Use Cases)
12. [Initial Access](#initial-access) (3 Use Cases)

---

## Credential Access

### Risikoherleitung fuer Banken

Credential-Angriffe bedrohen direkt den Zugang zu Kernbanksystemen (SWIFT, T2, Treasury), Kundenkonten und privilegierten Administratorzugaengen. Ein kompromittiertes Dienstkonto kann zu unautorisierte Transaktionen, Manipulation von Kontodaten oder Zugang zu regulatorisch geschuetzten Kundendaten (PII/PCI-DSS) fuehren. Die Risikoeinstufung ist KRITISCH da der Verlust von Credentials unmittelbaren finanziellen Schaden und regulatorische Konsequenzen (DSGVO Art. 33, DORA Art. 19) nach sich ziehen kann.

### Reale Vorfaelle (letzte 5 Jahre)

**Bangladesh Bank SWIFT Heist (2016)**
  Lazarus Group stahl SWIFT-Credentials der Bangladesh Bank und transferierte 81 Mio. USD. Angreifer nutzten Keylogger und Credential Dumping um SWIFT-Zugangsdaten zu erlangen.
  Quelle: [https://www.wired.com/2016/05/insane-81m-bangladesh-bank-heist-heres-know/](https://www.wired.com/2016/05/insane-81m-bangladesh-bank-heist-heres-know/)

**Capital One Data Breach (2019)**
  Ehemalige AWS-Mitarbeiterin nutzte gestohlene WAF-Credentials und SSRF um auf 106 Mio. Kundendaten zuzugreifen. IAM-Role-Credentials wurden via Metadata-Service extrahiert.
  Quelle: [https://www.capitalone.com/digital/facts2019/](https://www.capitalone.com/digital/facts2019/)

**Banco de Chile Lazarus Attack (2018)**
  Lazarus Group kompromittierte das SWIFT-System der Banco de Chile durch Credential Theft und Wiper-Malware (KillDisk). 10 Mio. USD wurden gestohlen.
  Quelle: [https://www.zdnet.com/article/lazarus-hackers-hit-banco-de-chile-with-killmbr-wiper/](https://www.zdnet.com/article/lazarus-hackers-hit-banco-de-chile-with-killmbr-wiper/)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 9 Abs. 2 (Zugangsrechte) |
| DORA | Art. 13 (Zugangskontrollen) |
| DORA | Art. 25 (IKT-Resilienztests) |
| EZB/TIBER-EU | TIBER-EU Active Phase: Credential Harvesting |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-001: Credential Access Detection - Credential Dumping

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Erkennung von OS Credential Dumping (LSASS, SAM, NTDS, DCSync) |
| **MITRE ATT&CK** | [T1003](https://attack.mitre.org/techniques/T1003/) (Credential Dumping), [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory), [T1003.002](https://attack.mitre.org/techniques/T1003/002/) (OS Credential Dumping: Security Account Manager), [T1003.003](https://attack.mitre.org/techniques/T1003/003/) (OS Credential Dumping: NTDS), [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync), [T1003.007](https://attack.mitre.org/techniques/T1003/007/) (OS Credential Dumping: Proc Filesystem), [T1003.008](https://attack.mitre.org/techniques/T1003/008/) (OS Credential Dumping: /etc/passwd and /etc/shadow) |

#### UC-BANK-002: Credential Access Detection - Network Sniffing

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Netzwerk-Traffic-Sniffing fuer Credential-Theft |
| **MITRE ATT&CK** | [T1040](https://attack.mitre.org/techniques/T1040/) (Network Sniffing) |

#### UC-BANK-003: Credential Access Detection - Process Injection: Portable Executable Injection

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Code-Injection in laufende Prozesse - Process Injection: Portable Executable Injection |
| **MITRE ATT&CK** | [T1055.002](https://attack.mitre.org/techniques/T1055/002/) (Process Injection: Portable Executable Injection) |

#### UC-BANK-004: Credential Access Detection - Brute Force: Password Spraying

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Brute-Force Angriff auf Zugangsdaten - Brute Force: Password Spraying |
| **MITRE ATT&CK** | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) (Brute Force: Password Spraying) |

#### UC-BANK-005: Credential Access Detection - Steal Application Access Token

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Steal Application Access Token |
| **MITRE ATT&CK** | [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token) |

#### UC-BANK-006: Credential Access Detection - Unsecured Credentials

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Ungesicherte Credentials in Dateien/Registry |
| **MITRE ATT&CK** | [T1552](https://attack.mitre.org/techniques/T1552/) (Unsecured Credentials), [T1552.001](https://attack.mitre.org/techniques/T1552/001/) (Unsecured Credentials: Credentials In Files), [T1552.002](https://attack.mitre.org/techniques/T1552/002/) (Unsecured Credentials: Credentials in Registry), [T1552.003](https://attack.mitre.org/techniques/T1552/003/) (Unsecured Credentials: Bash History), [T1552.004](https://attack.mitre.org/techniques/T1552/004/) (Unsecured Credentials: Private Keys), [T1552.005](https://attack.mitre.org/techniques/T1552/005/) (Unsecured Credentials: Cloud Instance Metadata API) |

#### UC-BANK-007: Credential Access Detection - Credentials from Password Stores: Credentials f...

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Browser-Credentials Extraktion |
| **MITRE ATT&CK** | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) (Credentials from Password Stores: Credentials from Web Browsers), [T1555.004](https://attack.mitre.org/techniques/T1555/004/) (Credentials from Password Stores: Windows Credential Manager) |

#### UC-BANK-008: Credential Access Detection - Steal or Forge Kerberos Tickets: Silver Ticket

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Kerberos Ticket Manipulation - Steal or Forge Kerberos Tickets: Silver Ticket |
| **MITRE ATT&CK** | [T1558.002](https://attack.mitre.org/techniques/T1558/002/) (Steal or Forge Kerberos Tickets: Silver Ticket), [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Steal or Forge Kerberos Tickets: Kerberoasting) |

---

## Privilege Escalation

### Risikoherleitung fuer Banken

Privilege Escalation ermoeglicht Angreifern den Zugang zu Systemen und Daten die ueber ihre initialen Rechte hinausgehen. In Bankumgebungen kann dies den Zugang zu Kernbanksystemen, Zahlungsverkehr (SEPA/SWIFT), Risikomanagement-Tools oder Administrator-Konsolen bedeuten. MaRisk AT 7.2 fordert explizit die Durchsetzung des Least-Privilege-Prinzips.

### Reale Vorfaelle (letzte 5 Jahre)

**SolarWinds/SUNBURST Finanzsektor (2020)**
  APT29 nutzte Token-Manipulation und Golden-SAML-Angriffe um privilegierten Zugang zu Cloud-Diensten von Finanzinstituten zu erlangen.
  Quelle: [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain.html)

**Tesco Bank Fraud (2016)**
  Angreifer eskalierten Rechte im Online-Banking-System und fuehrten 9.000 unautorisierte Transaktionen durch. 2,5 Mio. GBP Schaden.
  Quelle: [https://www.bbc.com/news/business-37906131](https://www.bbc.com/news/business-37906131)

**Carbanak/FIN7 Banking Campaign (2021)**
  Carbanak-Gruppe nutzte UAC-Bypasses und Token-Impersonation um Administratorzugang auf Bankservern zu erlangen.
  Quelle: [https://www.group-ib.com/blog/corkow/](https://www.group-ib.com/blog/corkow/)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 9 Abs. 3 (Privilegienverwaltung) |
| DORA | Art. 13 (Zugangskontrollen) |
| DORA | Art. 25 |
| EZB/TIBER-EU | TIBER-EU Active Phase: Privilege Escalation |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-020: Privilege Escalation Detection - Process Injection

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Code-Injection in laufende Prozesse |
| **MITRE ATT&CK** | [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) |

#### UC-BANK-021: Privilege Escalation Detection - Access Token Manipulation: Token Impersonati...

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Token-Manipulation fuer erhoehte Rechte - Access Token Manipulation: Token Impersonation/Theft |
| **MITRE ATT&CK** | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) (Access Token Manipulation: Token Impersonation/Theft) |

#### UC-BANK-022: Privilege Escalation Detection - Abuse Elevation Control Mechanism

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | UAC-Bypass und Rechteeskalation |
| **MITRE ATT&CK** | [T1548](https://attack.mitre.org/techniques/T1548/) (Abuse Elevation Control Mechanism), [T1548.001](https://attack.mitre.org/techniques/T1548/001/) (Abuse Elevation Control Mechanism: Setuid and Setgid), [T1548.002](https://attack.mitre.org/techniques/T1548/002/) (Abuse Elevation Control Mechanism: Bypass User Access Control) |

#### UC-BANK-023: Privilege Escalation Detection - Hijack Execution Flow: Services File Permiss...

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Schwache Service-Binary-Berechtigungen |
| **MITRE ATT&CK** | [T1574.010](https://attack.mitre.org/techniques/T1574/010/) (Hijack Execution Flow: Services File Permissions Weakness), [T1574.011](https://attack.mitre.org/techniques/T1574/011/) (Hijack Execution Flow: Services Registry Permissions Weakness) |

#### UC-BANK-024: Privilege Escalation Detection - Escape to Host

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Escape to Host |
| **MITRE ATT&CK** | [T1611](https://attack.mitre.org/techniques/T1611/) (Escape to Host) |

---

## Lateral Movement

### Risikoherleitung fuer Banken

Laterale Bewegung bedroht die Netzwerksegmentierung die gemaess DORA Art. 9 zwischen Office-IT, Kernbanksystemen und DMZ bestehen muss. Erfolgreiche Lateral-Movement-Angriffe koennen zur Kompromittierung von SWIFT-Servern, Datenbank-Servern mit Kundendaten oder Payment-Processing-Systemen fuehren. Die BaFin prueft die Wirksamkeit der Segmentierung im Rahmen von IT-Pruefungen.

### Reale Vorfaelle (letzte 5 Jahre)

**JPMorgan Chase Breach (2014)**
  Angreifer bewegten sich lateral durch 90+ Server nach initialem VPN-Zugang. 76 Mio. Haushalte und 7 Mio. Unternehmen betroffen.
  Quelle: [https://www.nytimes.com/2014/10/03/business/dealbook/jpmorgan-discovers-further-cyber-security-issues.html](https://www.nytimes.com/2014/10/03/business/dealbook/jpmorgan-discovers-further-cyber-security-issues.html)

**SWIFT-Netzwerk Bangladesh/Vietnam/Ecuador (2016-2018)**
  Lazarus nutzte PsExec und WMI fuer Lateral Movement zu SWIFT-Alliance-Servern in mehreren Banken weltweit.
  Quelle: [https://www.symantec.com/connect/blogs/swift-attackers-malware-linked-more-financial-attacks](https://www.symantec.com/connect/blogs/swift-attackers-malware-linked-more-financial-attacks)

**Scattered Spider Casino/Finance Attacks (2023)**
  Scattered Spider nutzte RDP, SSH und VPN-Pivoting fuer laterale Bewegung in Finanz- und Casino-Unternehmen nach Social Engineering.
  Quelle: [https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 9 Abs. 1 (Netzwerksegmentierung) |
| DORA | Art. 25 (Segmentierungstest) |
| DORA | Art. 10 (Anomalieerkennung) |
| EZB/TIBER-EU | TIBER-EU Active Phase: Lateral Movement |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-030: Lateral Movement Detection - Remote Services: Remote Desktop Protocol

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | RDP-basiertes Lateral Movement |
| **MITRE ATT&CK** | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) (Remote Services: Remote Desktop Protocol), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares), [T1021.003](https://attack.mitre.org/techniques/T1021/003/) (Remote Services: Distributed Component Object Model), [T1021.004](https://attack.mitre.org/techniques/T1021/004/) (Remote Services: SSH), [T1021.006](https://attack.mitre.org/techniques/T1021/006/) (Remote Services: Windows Remote Management) |

#### UC-BANK-031: Lateral Movement Detection - Boot or Logon Initialization Scripts: Startup Items

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Boot oder Logon Initialization Scripts - Boot or Logon Initialization Scripts: Startup Items |
| **MITRE ATT&CK** | [T1037.005](https://attack.mitre.org/techniques/T1037/005/) (Boot or Logon Initialization Scripts: Startup Items) |

#### UC-BANK-032: Lateral Movement Detection - Ingress Tool Transfer

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Download von Tools auf Zielsystem (Ingress Tool Transfer) |
| **MITRE ATT&CK** | [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer) |

#### UC-BANK-033: Lateral Movement Detection - Use Alternate Authentication Material: Pass the ...

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Use Alternate Authentication Material - Use Alternate Authentication Material: Pass the Hash |
| **MITRE ATT&CK** | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash) |

#### UC-BANK-034: Lateral Movement Detection - Lateral Tool Transfer

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Lateral Tool Transfer |
| **MITRE ATT&CK** | [T1570](https://attack.mitre.org/techniques/T1570/) (Lateral Tool Transfer) |

---

## Defense Evasion

### Risikoherleitung fuer Banken

Defense-Evasion-Techniken testen die Erkennungsfaehigkeit der Sicherheitsinfrastruktur (EDR, SIEM, IDS/IPS). Wenn Angreifer Sicherheitstools deaktivieren oder umgehen koennen, werden alle nachfolgenden Angriffsphasen unsichtbar. DORA Art. 10 fordert die Faehigkeit zur Erkennung anomaler Aktivitaeten - Defense Evasion testet genau diese Anforderung.

### Reale Vorfaelle (letzte 5 Jahre)

**Carbanak APT Defense Evasion (2022)**
  Carbanak-Varianten nutzten Process Injection, Timestomping und signierte Binaries um EDR auf Bankservern zu umgehen.
  Quelle: [https://malpedia.caad.fkie.fraunhofer.de/details/win.carbanak](https://malpedia.caad.fkie.fraunhofer.de/details/win.carbanak)

**QakBot Banking Trojan (2023)**
  QakBot nutzte DLL-Sideloading, Process Hollowing und Obfuscation um Banken-Sicherheitssoftware zu umgehen.
  Quelle: [https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-242a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-242a)

**RansomHub Defense Evasion (2024)**
  RansomHub deaktivierte EDR/AV-Loesungen auf Bankinfrastruktur vor Ransomware-Deployment via EDRKillShifter-Tool.
  Quelle: [https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 10 (Erkennung anomaler Aktivitaeten) |
| DORA | Art. 25 (Erkennungsfaehigkeitstest) |
| EZB/TIBER-EU | TIBER-EU Active Phase: Evasion Techniques |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-040: Defense Evasion Detection - Indicator Removal on Host: File Deletion

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Indicator Removal on Host: File Deletion |
| **MITRE ATT&CK** | [7.A.5](https://attack.mitre.org/techniques/7/A/5/) (Indicator Removal on Host: File Deletion) |

#### UC-BANK-041: Defense Evasion Detection - Direct Volume Access

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Direct Volume Access |
| **MITRE ATT&CK** | [T1006](https://attack.mitre.org/techniques/T1006/) (Direct Volume Access) |

#### UC-BANK-042: Defense Evasion Detection - Rootkit

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Rootkit |
| **MITRE ATT&CK** | [T1014](https://attack.mitre.org/techniques/T1014/) (Rootkit) |

#### UC-BANK-043: Defense Evasion Detection - Obfuscated Files or Information

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Verschleierte Dateien oder Informationen |
| **MITRE ATT&CK** | [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information), [T1027.002](https://attack.mitre.org/techniques/T1027/002/) (Obfuscated Files or Information: Software Packing), [T1027.013](https://attack.mitre.org/techniques/T1027/013/) (Obfuscated Files or Information: Encrypted/Encoded File) |

#### UC-BANK-044: Defense Evasion Detection - Masquerading: Masquerade Task or Service

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Tarnung als legitimer Prozess oder Datei (Masquerading) - Masquerading: Masquerade Task or Service |
| **MITRE ATT&CK** | [T1036.004](https://attack.mitre.org/techniques/T1036/004/) (Masquerading: Masquerade Task or Service), [T1036.005](https://attack.mitre.org/techniques/T1036/005/) (Masquerading: Match Legitimate Name or Location) |

#### UC-BANK-045: Defense Evasion Detection - Process Injection: Dynamic-link Library Injection

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Code-Injection in laufende Prozesse - Process Injection: Dynamic-link Library Injection |
| **MITRE ATT&CK** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) (Process Injection: Dynamic-link Library Injection) |

#### UC-BANK-046: Defense Evasion Detection - Indicator Removal on Host

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Loeschung von Indikatoren und Spuren |
| **MITRE ATT&CK** | [T1070](https://attack.mitre.org/techniques/T1070/) (Indicator Removal on Host), [T1070.001](https://attack.mitre.org/techniques/T1070/001/) (Indicator Removal on Host: Clear Windows Event Logs), [T1070.003](https://attack.mitre.org/techniques/T1070/003/) (Indicator Removal on Host: Clear Command History), [T1070.004](https://attack.mitre.org/techniques/T1070/004/) (Indicator Removal on Host: File Deletion), [T1070.006](https://attack.mitre.org/techniques/T1070/006/) (Indicator Removal on Host: Timestomp), [T1070.008](https://attack.mitre.org/techniques/T1070/008/) (Email Collection: Mailbox Manipulation) |

#### UC-BANK-047: Defense Evasion Detection - Modify Registry

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Windows Registry Modifikation |
| **MITRE ATT&CK** | [T1112](https://attack.mitre.org/techniques/T1112/) (Modify Registry) |

#### UC-BANK-048: Defense Evasion Detection - Access Token Manipulation

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Token-Manipulation fuer erhoehte Rechte |
| **MITRE ATT&CK** | [T1134](https://attack.mitre.org/techniques/T1134/) (Access Token Manipulation), [T1134.002](https://attack.mitre.org/techniques/T1134/002/) (Access Token Manipulation: Create Process with Token) |

#### UC-BANK-049: Defense Evasion Detection - Deobfuscate/Decode Files or Information

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Deobfuskation/Dekodierung von Dateien |
| **MITRE ATT&CK** | [T1140](https://attack.mitre.org/techniques/T1140/) (Deobfuscate/Decode Files or Information) |

#### UC-BANK-050: Defense Evasion Detection - Indirect Command Execution

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Indirect Command Execution |
| **MITRE ATT&CK** | [T1202](https://attack.mitre.org/techniques/T1202/) (Indirect Command Execution) |

#### UC-BANK-051: Defense Evasion Detection - Rogue Domain Controller

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Rogue Domain Controller |
| **MITRE ATT&CK** | [T1207](https://attack.mitre.org/techniques/T1207/) (Rogue Domain Controller) |

#### UC-BANK-052: Defense Evasion Detection - Signed Script Proxy Execution

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Signed Script Proxy Execution |
| **MITRE ATT&CK** | [T1216](https://attack.mitre.org/techniques/T1216/) (Signed Script Proxy Execution) |

#### UC-BANK-053: Defense Evasion Detection - Signed Binary Proxy Execution

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | System Binary Proxy Execution |
| **MITRE ATT&CK** | [T1218](https://attack.mitre.org/techniques/T1218/) (Signed Binary Proxy Execution), [T1218.003](https://attack.mitre.org/techniques/T1218/003/) (Signed Binary Proxy Execution: CMSTP), [T1218.004](https://attack.mitre.org/techniques/T1218/004/) (Signed Binary Proxy Execution: InstallUtil), [T1218.005](https://attack.mitre.org/techniques/T1218/005/) (Signed Binary Proxy Execution: Mshta), [T1218.007](https://attack.mitre.org/techniques/T1218/007/) (Signed Binary Proxy Execution: Msiexec), [T1218.008](https://attack.mitre.org/techniques/T1218/008/) (Signed Binary Proxy Execution: Odbcconf), [T1218.009](https://attack.mitre.org/techniques/T1218/009/) (Signed Binary Proxy Execution: Regsvcs/Regasm) |

#### UC-BANK-054: Defense Evasion Detection - XSL Script Processing

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | XSL Script Processing |
| **MITRE ATT&CK** | [T1220](https://attack.mitre.org/techniques/T1220/) (XSL Script Processing) |

#### UC-BANK-055: Defense Evasion Detection - File and Directory Permissions Modification

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von File and Directory Permissions Modification |
| **MITRE ATT&CK** | [T1222](https://attack.mitre.org/techniques/T1222/) (File and Directory Permissions Modification), [T1222.001](https://attack.mitre.org/techniques/T1222/001/) (File and Directory Permissions Modification: Windows File and Directory Permissions Modification), [T1222.002](https://attack.mitre.org/techniques/T1222/002/) (File and Directory Permissions Modification: FreeBSD, Linux and Mac File and Directory Permissions Modification) |

#### UC-BANK-056: Defense Evasion Detection - Virtualization/Sandbox Evasion: System Checks

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Sandbox-Erkennung und Umgehung - Virtualization/Sandbox Evasion: System Checks |
| **MITRE ATT&CK** | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) (Virtualization/Sandbox Evasion: System Checks), [T1497.003](https://attack.mitre.org/techniques/T1497/003/) (Virtualization/Sandbox Evasion: Time Based Evasion) |

#### UC-BANK-057: Defense Evasion Detection - Subvert Trust Controls: Mark-of-the-Web Bypass

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Subvert Trust Controls: Mark-of-the-Web Bypass |
| **MITRE ATT&CK** | [T1553.005](https://attack.mitre.org/techniques/T1553/005/) (Subvert Trust Controls: Mark-of-the-Web Bypass) |

#### UC-BANK-058: Defense Evasion Detection - Impair Defenses

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Deaktivierung von Sicherheitsmechanismen |
| **MITRE ATT&CK** | [T1562](https://attack.mitre.org/techniques/T1562/) (Impair Defenses), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) (Impair Defenses: Disable or Modify Tools), [T1562.010](https://attack.mitre.org/techniques/T1562/010/) (Impair Defenses: Downgrade Attack), [T1562.012](https://attack.mitre.org/techniques/T1562/012/) (Impair Defenses: Disable or Modify Linux Audit System) |

#### UC-BANK-059: Defense Evasion Detection - Hide Artifacts: Hidden Users

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Hide Artifacts: Hidden Users |
| **MITRE ATT&CK** | [T1564.002](https://attack.mitre.org/techniques/T1564/002/) (Hide Artifacts: Hidden Users), [T1564.004](https://attack.mitre.org/techniques/T1564/004/) (Hide Artifacts: NTFS File Attributes), [T1574.001](https://attack.mitre.org/techniques/T1574/001/) (Hijack Execution Flow - DLL Search Order Hijacking), [T1612](https://attack.mitre.org/techniques/T1612/) (Build Image on Host) |

---

## Discovery

### Risikoherleitung fuer Banken

Reconnaissance-Aktivitaeten zeigen an dass ein Angreifer bereits im Netzwerk ist und Ziele identifiziert. In Bankumgebungen kann dies die Identifikation von SWIFT-Terminals, Trading-Systemen, Datenbanken mit Kundendaten oder privilegierten Accounts bedeuten. Frueherkennung von Discovery-Aktivitaeten ermoeglicht die Unterbrechung der Kill-Chain bevor Schaden entsteht.

### Reale Vorfaelle (letzte 5 Jahre)

**APT38/Lazarus Bank Reconnaissance (2018-2022)**
  Lazarus/APT38 fuehrte systematische AD-Enumeration und Netzwerk-Scanning in Banken durch bevor SWIFT-Systeme angegriffen wurden.
  Quelle: [https://content.fireeye.com/apt/rpt-apt38](https://content.fireeye.com/apt/rpt-apt38)

**FIN7 Financial Discovery (2021)**
  FIN7 nutzte BloodHound/SharpHound und PowerView fuer Active-Directory-Reconnaissance in Retail-Banken.
  Quelle: [https://www.mandiant.com/resources/blog/fin7-evolves](https://www.mandiant.com/resources/blog/fin7-evolves)

**Volt Typhoon Living-off-the-Land (2023)**
  Volt Typhoon nutzte native Windows-Tools (netstat, systeminfo, nltest) fuer stille Reconnaissance in kritischer Infrastruktur inkl. Finanzsektor.
  Quelle: [https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure/](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure/)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 10 (Anomalieerkennung) |
| DORA | Art. 25 (IKT-Resilienztests) |
| EZB/TIBER-EU | TIBER-EU Active Phase: Reconnaissance |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-060: Discovery and Reconnaissance Detection - System Service Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | System Service Discovery |
| **MITRE ATT&CK** | [T1007](https://attack.mitre.org/techniques/T1007/) (System Service Discovery) |

#### UC-BANK-061: Discovery and Reconnaissance Detection - Application Window Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Anwendungsfenster-Enumeration |
| **MITRE ATT&CK** | [T1010](https://attack.mitre.org/techniques/T1010/) (Application Window Discovery) |

#### UC-BANK-062: Discovery and Reconnaissance Detection - Query Registry

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Windows Registry Abfrage |
| **MITRE ATT&CK** | [T1012](https://attack.mitre.org/techniques/T1012/) (Query Registry) |

#### UC-BANK-063: Discovery and Reconnaissance Detection - System Network Configuration Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Netzwerkkonfigurations-Enumeration |
| **MITRE ATT&CK** | [T1016](https://attack.mitre.org/techniques/T1016/) (System Network Configuration Discovery), [T1016.001](https://attack.mitre.org/techniques/T1016/001/) (System Network Configuration Discovery: Internet Connection Discovery) |

#### UC-BANK-064: Discovery and Reconnaissance Detection - Remote System Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Erkennung von Remote-System-Discovery und Host-Scanning |
| **MITRE ATT&CK** | [T1018](https://attack.mitre.org/techniques/T1018/) (Remote System Discovery) |

#### UC-BANK-065: Discovery and Reconnaissance Detection - Password Policy Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Nutzung von Remote-Services fuer Lateral Movement |
| **MITRE ATT&CK** | [T1021](https://attack.mitre.org/techniques/T1021/) (Password Policy Discovery) |

#### UC-BANK-066: Discovery and Reconnaissance Detection - System Owner/User Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | System Owner/User Discovery |
| **MITRE ATT&CK** | [T1033](https://attack.mitre.org/techniques/T1033/) (System Owner/User Discovery) |

#### UC-BANK-067: Discovery and Reconnaissance Detection - Network Service Scanning

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Netzwerk-Service-Scanning |
| **MITRE ATT&CK** | [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Scanning) |

#### UC-BANK-068: Discovery and Reconnaissance Detection - System Network Connections Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | System-Netzwerkverbindungen auflisten |
| **MITRE ATT&CK** | [T1049](https://attack.mitre.org/techniques/T1049/) (System Network Connections Discovery) |

#### UC-BANK-069: Discovery and Reconnaissance Detection - Process Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Prozess-Auflistung und -Discovery |
| **MITRE ATT&CK** | [T1057](https://attack.mitre.org/techniques/T1057/) (Process Discovery) |

#### UC-BANK-070: Discovery and Reconnaissance Detection - Permission Groups Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Berechtigungsgruppen-Discovery |
| **MITRE ATT&CK** | [T1069](https://attack.mitre.org/techniques/T1069/) (Permission Groups Discovery), [T1069.001](https://attack.mitre.org/techniques/T1069/001/) (Permission Groups Discovery: Local Groups), [T1069.002](https://attack.mitre.org/techniques/T1069/002/) (Permission Groups Discovery: Domain Groups) |

#### UC-BANK-071: Discovery and Reconnaissance Detection - System Information Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | System-Informationssammlung |
| **MITRE ATT&CK** | [T1082](https://attack.mitre.org/techniques/T1082/) (System Information Discovery) |

#### UC-BANK-072: Discovery and Reconnaissance Detection - File and Directory Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Dateisystem-Enumeration |
| **MITRE ATT&CK** | [T1083](https://attack.mitre.org/techniques/T1083/) (File and Directory Discovery) |

#### UC-BANK-073: Discovery and Reconnaissance Detection - Account Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Benutzerkonten-Enumeration |
| **MITRE ATT&CK** | [T1087](https://attack.mitre.org/techniques/T1087/) (Account Discovery), [T1087.001](https://attack.mitre.org/techniques/T1087/001/) (Account Discovery: Local Account), [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account) |

#### UC-BANK-074: Discovery and Reconnaissance Detection - Peripheral Device Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Erkennung von Peripheral Device Discovery |
| **MITRE ATT&CK** | [T1120](https://attack.mitre.org/techniques/T1120/) (Peripheral Device Discovery) |

#### UC-BANK-075: Discovery and Reconnaissance Detection - System Time Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Erkennung von System Time Discovery |
| **MITRE ATT&CK** | [T1124](https://attack.mitre.org/techniques/T1124/) (System Time Discovery) |

#### UC-BANK-076: Discovery and Reconnaissance Detection - Network Share Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Netzwerk Share Discovery |
| **MITRE ATT&CK** | [T1135](https://attack.mitre.org/techniques/T1135/) (Network Share Discovery) |

#### UC-BANK-077: Discovery and Reconnaissance Detection - Password Policy Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Password Policy Discovery |
| **MITRE ATT&CK** | [T1201](https://attack.mitre.org/techniques/T1201/) (Password Policy Discovery) |

#### UC-BANK-078: Discovery and Reconnaissance Detection - Browser Bookmark Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Browser Information Discovery |
| **MITRE ATT&CK** | [T1217](https://attack.mitre.org/techniques/T1217/) (Browser Bookmark Discovery) |

#### UC-BANK-079: Discovery and Reconnaissance Detection - Domain Trust Discovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Domain Trust Enumeration |
| **MITRE ATT&CK** | [T1482](https://attack.mitre.org/techniques/T1482/) (Domain Trust Discovery), [T1518](https://attack.mitre.org/techniques/T1518/) (Software Discovery), [T1518.001](https://attack.mitre.org/techniques/T1518/001/) (Software Discovery: Security Software Discovery), [T1526](https://attack.mitre.org/techniques/T1526/) (Cloud Service Discovery), [T1580](https://attack.mitre.org/techniques/T1580/) (Cloud Infrastructure Discovery), [T1614.001](https://attack.mitre.org/techniques/T1614/001/) (System Location Discovery: System Language Discovery), [T1654](https://attack.mitre.org/techniques/T1654/) (Log Enumeration), [TA0007](https://attack.mitre.org/techniques/TA0007/) (host discovery) |

---

## Execution

### Risikoherleitung fuer Banken

Ausfuehrung von boeartiger Software auf Bankinfrastruktur kann zur Installation von Banking-Trojanern, Keyloggern oder Ransomware fuehren. PowerShell-basierte Angriffe sind besonders relevant da PowerShell auf allen Windows-Bankarbeitsplaetzen verfuegbar ist. BAIT fordert restriktive Application-Control-Massnahmen.

### Reale Vorfaelle (letzte 5 Jahre)

**Emotet Banking Trojan (2022)**
  Emotet nutzte PowerShell-Downloader und WMI fuer initiale Ausfuehrung bei Banken und Finanzdienstleistern.
  Quelle: [https://www.europol.europa.eu/media-press/newsroom/news/world%E2%80%99s-most-dangerous-malware-emotet-disrupted-through-global-action](https://www.europol.europa.eu/media-press/newsroom/news/world%E2%80%99s-most-dangerous-malware-emotet-disrupted-through-global-action)

**IcedID/BokBot Banking Malware (2023)**
  IcedID nutzte Scheduled Tasks und COM-Hijacking fuer persistente Ausfuehrung auf Bankarbeitsplaetzen.
  Quelle: [https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid](https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid)

**TrickBot Banking Operations (2021)**
  TrickBot nutzte PowerShell-basierte Module und Service-Erstellung fuer Execution auf Bankinfrastruktur.
  Quelle: [https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-076a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-076a)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 10 (Erkennung anomaler Aktivitaeten) |
| DORA | Art. 25 (IKT-Resilienztests) |
| DORA | Art. 9 (Schutzmassnahmen) |
| EZB/TIBER-EU | TIBER-EU Active Phase: Execution |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-080: Suspicious Execution Detection - Masquerading: Right-to-Left Override

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Tarnung als legitimer Prozess oder Datei (Masquerading) - Masquerading: Right-to-Left Override |
| **MITRE ATT&CK** | [T1036.002](https://attack.mitre.org/techniques/T1036/002/) (Masquerading: Right-to-Left Override) |

#### UC-BANK-081: Suspicious Execution Detection - Windows Management Instrumentation

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Windows Management Instrumentation Ausfuehrung |
| **MITRE ATT&CK** | [T1047](https://attack.mitre.org/techniques/T1047/) (Windows Management Instrumentation) |

#### UC-BANK-082: Suspicious Execution Detection - Scheduled Task/Job: Scheduled Task

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Persistenz via geplante Aufgaben (Scheduled Task/Job) - Scheduled Task/Job: Scheduled Task |
| **MITRE ATT&CK** | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task/Job: Scheduled Task) |

#### UC-BANK-083: Suspicious Execution Detection - Command and Scripting Interpreter: PowerShell

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | PowerShell-basierte Ausfuehrung |
| **MITRE ATT&CK** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (Command and Scripting Interpreter: PowerShell), [T1059.002](https://attack.mitre.org/techniques/T1059/002/) (Command and Scripting Interpreter: AppleScript), [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Command and Scripting Interpreter: Windows Command Shell), [T1059.004](https://attack.mitre.org/techniques/T1059/004/) (Command and Scripting Interpreter: Bash), [T1059.005](https://attack.mitre.org/techniques/T1059/005/) (Command and Scripting Interpreter: Visual Basic), [T1059.006](https://attack.mitre.org/techniques/T1059/006/) (Command and Scripting Interpreter: Python) |

#### UC-BANK-084: Suspicious Execution Detection - Native API

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Native API Ausfuehrung |
| **MITRE ATT&CK** | [T1106](https://attack.mitre.org/techniques/T1106/) (Native API) |

#### UC-BANK-085: Suspicious Execution Detection - User Execution: Malicious File

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | User Execution - User Execution: Malicious File |
| **MITRE ATT&CK** | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File) |

#### UC-BANK-086: Suspicious Execution Detection - System Services: Launchctl

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Ausfuehrung via System-Services - System Services: Launchctl |
| **MITRE ATT&CK** | [T1569.001](https://attack.mitre.org/techniques/T1569/001/) (System Services: Launchctl), [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (System Services: Service Execution) |

#### UC-BANK-087: Suspicious Execution Detection - Cloud Administration Command

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Cloud Administration Command |
| **MITRE ATT&CK** | [T1651](https://attack.mitre.org/techniques/T1651/) (Cloud Administration Command) |

---

## Persistence

### Risikoherleitung fuer Banken

Persistenzmechanismen ermoeglichen langfristigen APT-Zugang zu Bankinfrastruktur. Lazarus-Gruppe hat in vergangenen Faellen monatelang unerkannt in Banknetzen operiert bevor SWIFT-Transaktionen manipuliert wurden. MaRisk fordert die regelmaessige Pruefung auf unautorisierte Aenderungen an Systemen.

### Reale Vorfaelle (letzte 5 Jahre)

**Lazarus Persistence in Financial Networks (2020)**
  Lazarus installierte Backdoors via Scheduled Tasks und modifizierte Systemdienste fuer langfristigen Zugang zu Banknetzen.
  Quelle: [https://securelist.com/lazarus-under-the-hood/77908/](https://securelist.com/lazarus-under-the-hood/77908/)

**DarkSide Ransomware Banking Persistence (2021)**
  DarkSide-Affiliates erstellten lokale Admin-Accounts und Registry-Run-Keys fuer Persistence vor Ransomware-Deployment.
  Quelle: [https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-131a)

**SilverTerrier BEC Persistence (2022)**
  Nigerianische BEC-Gruppe nutzte Outlook-Rules und WMI-Event-Subscriptions fuer Persistenz in Finanzabteilungen.
  Quelle: [https://unit42.paloaltonetworks.com/silverterrier-covid-19-themed-business-email-compromise/](https://unit42.paloaltonetworks.com/silverterrier-covid-19-themed-business-email-compromise/)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 10 (Anomalieerkennung) |
| DORA | Art. 12 (Backup-Policies) |
| DORA | Art. 25 |
| EZB/TIBER-EU | TIBER-EU Active Phase: Persistence Establishment |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-090: Persistence Mechanism Detection - Scheduled Task/Job: Cron

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Persistenz via geplante Aufgaben (Scheduled Task/Job) - Scheduled Task/Job: Cron |
| **MITRE ATT&CK** | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) (Scheduled Task/Job: Cron) |

#### UC-BANK-091: Persistence Mechanism Detection - Create Account: Local Account

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erstellung neuer Benutzerkonten - Create Account: Local Account |
| **MITRE ATT&CK** | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) (Create Account: Local Account), [T1136.002](https://attack.mitre.org/techniques/T1136/002/) (Create Account: Domain Account), [T1136.003](https://attack.mitre.org/techniques/T1136/003/) (Create Account: Cloud Account) |

#### UC-BANK-092: Persistence Mechanism Detection - Office Application Startup: Outlook Home Page

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Office Application Startup: Outlook Home Page |
| **MITRE ATT&CK** | [T1137.004](https://attack.mitre.org/techniques/T1137/004/) (Office Application Startup: Outlook Home Page) |

#### UC-BANK-093: Persistence Mechanism Detection - Signed Binary Proxy Execution: Rundll32

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | System Binary Proxy Execution - Signed Binary Proxy Execution: Rundll32 |
| **MITRE ATT&CK** | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) (Signed Binary Proxy Execution: Rundll32) |

#### UC-BANK-094: Persistence Mechanism Detection - Scheduled Task/Job: Cron

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Scheduled Task/Job: Cron |
| **MITRE ATT&CK** | [T1503.003](https://attack.mitre.org/techniques/T1503/003/) (Scheduled Task/Job: Cron) |

#### UC-BANK-095: Persistence Mechanism Detection - Server Software Component: Transport Agent

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Server Software Component: Transport Agent |
| **MITRE ATT&CK** | [T1505.002](https://attack.mitre.org/techniques/T1505/002/) (Server Software Component: Transport Agent), [T1505.003](https://attack.mitre.org/techniques/T1505/003/) (Server Software Component: Web Shell) |

#### UC-BANK-096: Persistence Mechanism Detection - Create or Modify System Process: Systemd Se...

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | System-Service-Erstellung und -Manipulation - Create or Modify System Process: Systemd Service |
| **MITRE ATT&CK** | [T1543.002](https://attack.mitre.org/techniques/T1543/002/) (Create or Modify System Process: Systemd Service), [T1543.003](https://attack.mitre.org/techniques/T1543/003/) (Create or Modify System Process: Windows Service) |

#### UC-BANK-097: Persistence Mechanism Detection - Event Triggered Execution: Windows Manageme...

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Event Triggered Execution - Event Triggered Execution: Windows Management Instrumentation Event Subscription |
| **MITRE ATT&CK** | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) (Event Triggered Execution: Windows Management Instrumentation Event Subscription), [T1546.011](https://attack.mitre.org/techniques/T1546/011/) (Application Shimming) |

#### UC-BANK-098: Persistence Mechanism Detection - Boot or Logon Autostart Execution: Registry...

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Boot/Logon Autostart Execution - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **MITRE ATT&CK** | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder), [T1547.004](https://attack.mitre.org/techniques/T1547/004/) (Boot or Logon Autostart Execution: Winlogon Helper DLL), [T1547.009](https://attack.mitre.org/techniques/T1547/009/) (Boot or Logon Autostart Execution: Shortcut Modification) |

---

## Exfiltration

### Risikoherleitung fuer Banken

Datenexfiltration stellt fuer Banken das hoechste Risiko dar: Kundendaten (DSGVO), Transaktionsdaten, Kreditakten, Handelspositionen. Eine Exfiltration loest DSGVO-Meldepflicht (72h) und DORA Art. 19 Meldepflicht an BaFin aus. Der Reputationsschaden kann existenzbedrohend sein.

### Reale Vorfaelle (letzte 5 Jahre)

**Capital One Exfiltration (2019)**
  106 Mio. Kundendatensaetze wurden via AWS CLI und S3-Buckets exfiltriert. Daten enthielten Kreditantraege und SSNs.
  Quelle: [https://www.justice.gov/usao-wdwa/press-release/file/1188626/download](https://www.justice.gov/usao-wdwa/press-release/file/1188626/download)

**Accellion FTA Financial Sector Breach (2021)**
  Clop-Ransomware-Gruppe exfiltrierte Finanzdaten ueber kompromittierte File-Transfer-Appliances bei Banken und Versicherungen.
  Quelle: [https://www.mandiant.com/resources/blog/accellion-fta-exploited-0-day](https://www.mandiant.com/resources/blog/accellion-fta-exploited-0-day)

**MOVEit Transfer Financial Exfiltration (2023)**
  Cl0p nutzte MOVEit-Schwachstelle zur Massenexfiltration von Finanzdaten bei Deutsche Bank, ING und weiteren Instituten.
  Quelle: [https://www.bleepingcomputer.com/news/security/clop-ransomware-moveit-extortion-attacks-hit-over-130-orgs/](https://www.bleepingcomputer.com/news/security/clop-ransomware-moveit-extortion-attacks-hit-over-130-orgs/)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 19 (Meldepflicht schwerwiegender Vorfaelle) |
| DORA | Art. 25 |
| DORA | Art. 17 (IKT-bezogene Vorfaelle) |
| EZB/TIBER-EU | TIBER-EU Active Phase: Data Exfiltration |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-100: Data Exfiltration Detection - Automated Exfiltration

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Automatisierte Datenexfiltration |
| **MITRE ATT&CK** | [T1020](https://attack.mitre.org/techniques/T1020/) (Automated Exfiltration) |

#### UC-BANK-101: Data Exfiltration Detection - Scheduled Transfer

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Geplante automatische Datenuebertragung |
| **MITRE ATT&CK** | [T1029](https://attack.mitre.org/techniques/T1029/) (Scheduled Transfer) |

#### UC-BANK-102: Data Exfiltration Detection - Data Transfer Size Limits

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Aufgeteilte Datenexfiltration in kleinen Stuecken |
| **MITRE ATT&CK** | [T1030](https://attack.mitre.org/techniques/T1030/) (Data Transfer Size Limits) |

#### UC-BANK-103: Data Exfiltration Detection - Exfiltration Over C2 Channel

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Datenexfiltration ueber C2-Kanal |
| **MITRE ATT&CK** | [T1041](https://attack.mitre.org/techniques/T1041/) (Exfiltration Over C2 Channel) |

#### UC-BANK-104: Data Exfiltration Detection - Exfiltration Over Unencrypted/Obfuscated Non-C2...

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Exfiltration ueber alternativen Protokollkanal - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol |
| **MITRE ATT&CK** | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) (Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol) |

#### UC-BANK-105: Data Exfiltration Detection - Transfer Data to Cloud Account

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Exfiltration zu Cloud-Accounts |
| **MITRE ATT&CK** | [T1537](https://attack.mitre.org/techniques/T1537/) (Transfer Data to Cloud Account) |

#### UC-BANK-106: Data Exfiltration Detection - Exfiltration to Code Repository

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Exfiltration ueber Webdienste - Exfiltration to Code Repository |
| **MITRE ATT&CK** | [T1567.001](https://attack.mitre.org/techniques/T1567/001/) (Exfiltration to Code Repository), [T1567.002](https://attack.mitre.org/techniques/T1567/002/) (Exfiltration to Cloud Storage) |

---

## Collection

### Risikoherleitung fuer Banken

Datensammlung auf Endpunkten (Screenshots, Keylogging, Clipboard) ermoeglicht Angreifern das Abfangen von Transaktionsfreigaben, TAN-Nummern, SWIFT-Codes oder internen Kommunikationen. Silence-Gruppe und Carbanak haben diese Techniken erfolgreich gegen Banken eingesetzt.

### Reale Vorfaelle (letzte 5 Jahre)

**Carbanak Screen Capture Banking (2015-2022)**
  Carbanak nutzte Screen-Capture und Keylogging um Bankmitarbeiter bei der Nutzung von SWIFT und Treasury-Systemen zu beobachten.
  Quelle: [https://securelist.com/the-great-bank-robbery-the-carbanak-apt/68732/](https://securelist.com/the-great-bank-robbery-the-carbanak-apt/68732/)

**Silence Group Banking Collection (2021)**
  Silence-Gruppe sammelte Screenshots und Clipboard-Daten von Bankarbeitsplaetzen um Transaktionsprozesse zu verstehen.
  Quelle: [https://www.group-ib.com/resources/research/silence-2.0-going-global/](https://www.group-ib.com/resources/research/silence-2.0-going-global/)

**Grandoreiro Banking Trojan (2024)**
  Grandoreiro nutzte Clipboard-Hijacking und Keylogging bei lateinamerikanischen und europaeischen Banken.
  Quelle: [https://www.welivesecurity.com/en/eset-research/grandoreiro-banking-trojan-disrupted/](https://www.welivesecurity.com/en/eset-research/grandoreiro-banking-trojan-disrupted/)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 10 (Anomalieerkennung) |
| DORA | Art. 25 |
| DORA | Art. 13 (Datenschutz) |
| EZB/TIBER-EU | TIBER-EU Active Phase: Data Collection |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-110: Data Collection Detection - Input Capture: Keylogging

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Input Capture: Keylogging |
| **MITRE ATT&CK** | [8.A.2](https://attack.mitre.org/techniques/8/A/2/) (Input Capture: Keylogging) |

#### UC-BANK-111: Data Collection Detection - Data from Local System

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Zugriff auf sensible lokale Dateien und Daten |
| **MITRE ATT&CK** | [T1005](https://attack.mitre.org/techniques/T1005/) (Data from Local System) |

#### UC-BANK-112: Data Collection Detection - Data from Removable Media

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Data from Removable Media |
| **MITRE ATT&CK** | [T1025](https://attack.mitre.org/techniques/T1025/) (Data from Removable Media) |

#### UC-BANK-113: Data Collection Detection - Data from Network Shared Drive

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Daten von Network Shared Drive |
| **MITRE ATT&CK** | [T1039](https://attack.mitre.org/techniques/T1039/) (Data from Network Shared Drive) |

#### UC-BANK-114: Data Collection Detection - Input Capture: Keylogging

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Input Capture - Tastatureingaben abfangen - Input Capture: Keylogging |
| **MITRE ATT&CK** | [T1056.001](https://attack.mitre.org/techniques/T1056/001/) (Input Capture: Keylogging) |

#### UC-BANK-115: Data Collection Detection - Data Staged: Local Data Staging

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Lokales Sammeln von Daten in Staging-Verzeichnissen |
| **MITRE ATT&CK** | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) (Data Staged: Local Data Staging) |

#### UC-BANK-116: Data Collection Detection - Screen Capture

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Bildschirmaufnahme / Screen Capture |
| **MITRE ATT&CK** | [T1113](https://attack.mitre.org/techniques/T1113/) (Screen Capture) |

#### UC-BANK-117: Data Collection Detection - Email Collection: Local Email Collection

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Email Collection: Local Email Collection |
| **MITRE ATT&CK** | [T1114.001](https://attack.mitre.org/techniques/T1114/001/) (Email Collection: Local Email Collection), [T1114.003](https://attack.mitre.org/techniques/T1114/003/) (Email Collection: Email Forwarding Rule) |

#### UC-BANK-118: Data Collection Detection - Clipboard Data

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Clipboard-Daten abgreifen |
| **MITRE ATT&CK** | [T1115](https://attack.mitre.org/techniques/T1115/) (Clipboard Data) |

#### UC-BANK-119: Data Collection Detection - Automated Collection

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Automatisierte Datensammlung |
| **MITRE ATT&CK** | [T1119](https://attack.mitre.org/techniques/T1119/) (Automated Collection), [T1123](https://attack.mitre.org/techniques/T1123/) (Audio Capture), [T1125](https://attack.mitre.org/techniques/T1125/) (Video Capture), [T1530](https://attack.mitre.org/techniques/T1530/) (Data from Cloud Storage Object), [T1560.001](https://attack.mitre.org/techniques/T1560/001/) (Archive Collected Data - Archive via Utility) |

---

## Command And Control

### Risikoherleitung fuer Banken

C2-Kommunikation zeigt aktive Fernsteuerung kompromittierter Banksysteme an. DNS-Tunneling und HTTPS-Beacons koennen die Netzwerk-Sicherheitsinfrastruktur umgehen. DORA Art. 9 fordert Netzwerkueberwachung die solche Kommunikationskanaele erkennen muss.

### Reale Vorfaelle (letzte 5 Jahre)

**Cobalt Group C2 Banking (2018)**
  Cobalt Group nutzte DNS-Tunneling und HTTPS-Beacons fuer C2-Kommunikation bei ATM-Angriffen auf Banken.
  Quelle: [https://www.group-ib.com/resources/research/cobalt/](https://www.group-ib.com/resources/research/cobalt/)

**FIN7 C2 Infrastructure (2022)**
  FIN7 nutzte legitime Cloud-Dienste (Google Sheets, Dropbox) als C2-Kanaele um Firewall-Regeln in Banken zu umgehen.
  Quelle: [https://www.mandiant.com/resources/blog/fin7-evolution-and-phishing-lnk](https://www.mandiant.com/resources/blog/fin7-evolution-and-phishing-lnk)

**Qilin Ransomware Proxy C2 (2024)**
  Qilin-Affiliates nutzten Reverse-Proxies und Non-Standard-Ports fuer C2 bei Angriffen auf Finanzdienstleister.
  Quelle: [https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-qilin](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-qilin)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 9 Abs. 1 (Netzwerkschutz) |
| DORA | Art. 10 (Anomalieerkennung) |
| DORA | Art. 25 |
| EZB/TIBER-EU | TIBER-EU Active Phase: C2 Establishment |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-120: C2 Communication Detection - Application Layer Protocol

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | C2-Kommunikation ueber Anwendungsprotokolle |
| **MITRE ATT&CK** | [T1071](https://attack.mitre.org/techniques/T1071/) (Application Layer Protocol), [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Application Layer Protocol: Web Protocols), [T1071.004](https://attack.mitre.org/techniques/T1071/004/) (Application Layer Protocol: DNS) |

#### UC-BANK-121: C2 Communication Detection - Proxy: Internal Proxy

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Proxy: Internal Proxy |
| **MITRE ATT&CK** | [T1090.001](https://attack.mitre.org/techniques/T1090/001/) (Proxy: Internal Proxy) |

#### UC-BANK-122: C2 Communication Detection - Data Encoding: Standard Encoding

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Data Encoding fuer C2 - Data Encoding: Standard Encoding |
| **MITRE ATT&CK** | [T1132.001](https://attack.mitre.org/techniques/T1132/001/) (Data Encoding: Standard Encoding) |

#### UC-BANK-123: C2 Communication Detection - Traffic Signaling

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Traffic Signaling |
| **MITRE ATT&CK** | [T1205](https://attack.mitre.org/techniques/T1205/) (Traffic Signaling) |

#### UC-BANK-124: C2 Communication Detection - Non-Standard Port

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Non-Standard Port C2 |
| **MITRE ATT&CK** | [T1571](https://attack.mitre.org/techniques/T1571/) (Non-Standard Port) |

#### UC-BANK-125: C2 Communication Detection - Protocol Tunneling

| Attribut | Wert |
|----------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Protocol Tunneling |
| **MITRE ATT&CK** | [T1572](https://attack.mitre.org/techniques/T1572/) (Protocol Tunneling) |

---

## Impact

### Risikoherleitung fuer Banken

Impact-Techniken (Ransomware, Datenvernichtung, Service-Stops) bedrohen direkt die Geschaeftskontinuitaet der Bank. DORA Art. 11 fordert umfassende Business-Continuity-Plaene. Ein Ransomware-Angriff kann den Zahlungsverkehr, Online-Banking und interne Systeme lahmlegen - wie beim ICBC-Angriff 2023 demonstriert.

### Reale Vorfaelle (letzte 5 Jahre)

**NotPetya Maersk/TNT Financial Impact (2017)**
  NotPetya-Wiper verursachte bei Maersk 300 Mio. USD Schaden. Mehrere Finanzinstitute waren ebenfalls betroffen durch verschluesselte Systeme.
  Quelle: [https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/](https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/)

**LockBit Royal Mail / Financial Sector (2023)**
  LockBit verschluesselte Systeme bei Finanzdienstleistern, stoppte Services und loeschte VSS-Snapshots.
  Quelle: [https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a)

**ICBC Ransomware Attack (2023)**
  LockBit-Angriff auf ICBC Financial Services (groesste Bank der Welt) stoerte US-Treasury-Handel. ICBC konnte Trades nicht mehr clearen.
  Quelle: [https://www.reuters.com/technology/cybersecurity/industrial-commercial-bank-china-hit-by-ransomware-attack-ft-2023-11-09/](https://www.reuters.com/technology/cybersecurity/industrial-commercial-bank-china-hit-by-ransomware-attack-ft-2023-11-09/)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 11 (Business-Continuity) |
| DORA | Art. 17 (IKT-Vorfaelle) |
| DORA | Art. 19 (Meldepflicht) |
| DORA | Art. 25 |
| EZB/TIBER-EU | TIBER-EU Active Phase: Impact Assessment |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-130: System Impact Detection - Data Encrypted for Impact

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Ransomware-Verschluesselung (Data Encrypted for Impact) |
| **MITRE ATT&CK** | [T1486](https://attack.mitre.org/techniques/T1486/) (Data Encrypted for Impact) |

#### UC-BANK-131: System Impact Detection - Service Stop

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Stoppen kritischer Dienste (Service Stop) |
| **MITRE ATT&CK** | [T1489](https://attack.mitre.org/techniques/T1489/) (Service Stop) |

#### UC-BANK-132: System Impact Detection - Inhibit System Recovery

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Inhibit System Recovery |
| **MITRE ATT&CK** | [T1490](https://attack.mitre.org/techniques/T1490/) (Inhibit System Recovery) |

#### UC-BANK-133: System Impact Detection - Defacement

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Defacement / Hinterlassen von Ransomware-Nachrichten |
| **MITRE ATT&CK** | [T1491](https://attack.mitre.org/techniques/T1491/) (Defacement) |

#### UC-BANK-134: System Impact Detection - Resource Hijacking

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Crypto-Mining auf Bankinfrastruktur (Resource Hijacking) |
| **MITRE ATT&CK** | [T1496](https://attack.mitre.org/techniques/T1496/) (Resource Hijacking) |

#### UC-BANK-135: System Impact Detection - Endpoint Denial of Service

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | System-Shutdown oder Endpoint DoS |
| **MITRE ATT&CK** | [T1499](https://attack.mitre.org/techniques/T1499/) (Endpoint Denial of Service) |

#### UC-BANK-136: System Impact Detection - System Shutdown/Reboot

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | System Shutdown/Reboot |
| **MITRE ATT&CK** | [T1529](https://attack.mitre.org/techniques/T1529/) (System Shutdown/Reboot) |

#### UC-BANK-137: System Impact Detection - Account Access Removal

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Erkennung von Account Access Removal |
| **MITRE ATT&CK** | [T1531](https://attack.mitre.org/techniques/T1531/) (Account Access Removal) |

#### UC-BANK-138: System Impact Detection - Disk Wipe: Disk Content Wipe

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Erkennung von Disk Wipe: Disk Content Wipe |
| **MITRE ATT&CK** | [T1561.001](https://attack.mitre.org/techniques/T1561/001/) (Disk Wipe: Disk Content Wipe) |

#### UC-BANK-139: System Impact Detection - Data Manipulation: Stored Data Manipulation

| Attribut | Wert |
|----------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Manipulation gespeicherter Daten |
| **MITRE ATT&CK** | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) (Data Manipulation: Stored Data Manipulation) |

---

## Initial Access

### Risikoherleitung fuer Banken

Initial Access ist der erste Schritt jeder Angriffskette. Phishing und kompromittierte Zugangsdaten sind die haeufigsten Eintrittsvektoren bei Banken. Die BaFin prueft Security-Awareness-Programme und technische Phishing-Abwehr im Rahmen von IT-Pruefungen.

### Reale Vorfaelle (letzte 5 Jahre)

**Phishing gegen Deutsche Bankkunden (2023)**
  Grossangelegte Phishing-Kampagnen gegen Kunden deutscher Banken (Sparkasse, Volksbank) mit taeuschend echten Login-Seiten.
  Quelle: [https://www.bsi.bund.de/DE/Themen/Verbraucherinnen-und-Verbraucher/Cyber-Sicherheitslage/Methoden-der-Cyber-Kriminalitaet/Spam-Phishing-Co/Passwortdiebstahl-durch-Phishing/passwortdiebstahl-durch-phishing_node.html](https://www.bsi.bund.de/DE/Themen/Verbraucherinnen-und-Verbraucher/Cyber-Sicherheitslage/Methoden-der-Cyber-Kriminalitaet/Spam-Phishing-Co/Passwortdiebstahl-durch-Phishing/passwortdiebstahl-durch-phishing_node.html)

**Magecart Attacks on Payment Portals (2022)**
  Magecart-Gruppen kompromittierten Zahlungsportale von Banken via Supply-Chain-Angriffe auf JavaScript-Libraries.
  Quelle: [https://www.riskiq.com/blog/labs/magecart-british-airways-breach/](https://www.riskiq.com/blog/labs/magecart-british-airways-breach/)

**Okta Breach Financial Impact (2023)**
  Okta-Breach ermoeglichte Angreifern Zugang zu IAM-Systemen von Finanzinstituten via gestohlene Session-Tokens.
  Quelle: [https://sec.okta.com/harfiles](https://sec.okta.com/harfiles)

### Regulatorische Grundlage

| Regulierung | Referenz |
|------------|---------|
| DORA | Art. 9 (Schutzmassnahmen) |
| DORA | Art. 13 (Zugangskontrollen) |
| DORA | Art. 25 |
| EZB/TIBER-EU | TIBER-EU Threat Intelligence Phase |
| BaFin MaRisk | AT 7.2 Informationssicherheit |
| BaFin BAIT | Abschnitt 5 Informationssicherheitsmanagement |

### Use Cases

#### UC-BANK-140: Initial Access Detection - Valid Accounts

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | initial-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Initial-Compromise |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Verwendung valider Accounts |
| **MITRE ATT&CK** | [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) |

#### UC-BANK-141: Initial Access Detection - Drive-By Compromise

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | initial-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Initial-Compromise |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Drive-by Compromise |
| **MITRE ATT&CK** | [T1189](https://attack.mitre.org/techniques/T1189/) (Drive-By Compromise) |

#### UC-BANK-142: Initial Access Detection - Phishing: Spearphishing Link

| Attribut | Wert |
|----------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | initial-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Initial-Compromise |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Erkennung von Phishing: Spearphishing Link |
| **MITRE ATT&CK** | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) (Phishing: Spearphishing Link) |

---

## Regulatorische Gesamtzuordnung

| DORA Artikel | Anforderung | Abdeckende Use Cases |
|-------------|-------------|---------------------|
| Art. 9 | Netzwerkschutz, Segmentierung | UC-030..034 (Lateral Movement), UC-120..125 (C2) |
| Art. 10 | Erkennung anomaler Aktivitaeten | UC-040..059 (Defense Evasion), UC-060..079 (Discovery), UC-999 (Kill Chain) |
| Art. 11 | Business Continuity | UC-130..139 (Impact) |
| Art. 12 | Backup und Wiederherstellung | UC-090..098 (Persistence), UC-130 (Ransomware) |
| Art. 13 | Zugangskontrollen | UC-001..008 (Credential Access), UC-020..024 (Privilege Escalation) |
| Art. 17 | IKT-bezogene Vorfaelle | UC-130..139 (Impact), UC-100..106 (Exfiltration) |
| Art. 19 | Meldepflicht | UC-100..106 (Exfiltration), UC-130..139 (Impact), UC-999 (Kill Chain) |
| Art. 25 | IKT-Resilienztests | Alle 111 Use Cases |
| Art. 26 | TLPT | Alle 16 Adversary-Profile |

| EZB/TIBER-EU | Phase | Use Cases |
|-------------|-------|-----------|
| Threat Intelligence | Reconnaissance | UC-060..079 |
| Active Phase | Credential Harvesting | UC-001..008 |
| Active Phase | Privilege Escalation | UC-020..024 |
| Active Phase | Lateral Movement | UC-030..034 |
| Active Phase | C2 Establishment | UC-120..125 |
| Active Phase | Data Exfiltration | UC-100..106 |
| Active Phase | Impact | UC-130..139 |
| Closure | Reporting | ITSO-Bericht, Compliance-Dashboard |

---

*Dieses Dokument ist vertraulich und nur fuer autorisiertes Personal bestimmt.*
