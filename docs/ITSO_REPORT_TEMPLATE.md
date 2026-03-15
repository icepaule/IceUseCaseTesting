# ITSO-Bericht: Purple Team Testing

## Ergebnisbericht gemaess DORA Art. 26 / TIBER-EU

---

| Feld | Wert |
|------|------|
| **Institut** | [Bankname eintragen] |
| **BaFin-ID** | [BaFin-Registernummer] |
| **Berichtsdatum** | [YYYY-MM-DD] |
| **Berichtszeitraum** | [Von - Bis] |
| **Klassifikation** | VERTRAULICH |
| **Ersteller** | IT-Sicherheitsbeauftragter (ITSO) |
| **Freigabe** | [Vorstandsmitglied] |
| **Version** | 1.0 |

---

## 1. Executive Summary

### 1.1 Zweck

Dieser Bericht dokumentiert die Ergebnisse des automatisierten Purple Team Testings gemaess:
- DORA Art. 25 (Digitale operationale Resilienztests)
- DORA Art. 26 (TLPT - Threat-Led Penetration Testing)
- TIBER-EU Framework der EZB
- BaFin MaRisk AT 7.2 / BAIT Abschnitt 5

### 1.2 Scope

| Element | Details |
|---------|---------|
| Testumgebung | [Produktions-Spiegel / Testumgebung] |
| Getestete Systeme | [Anzahl] Server, [Anzahl] Clients |
| Plattformen | Windows Server, Windows 11, Ubuntu, RHEL |
| Netzwerksegmente | [Segmente auflisten] |
| Ausschlüsse | [Ausschlüsse dokumentieren] |

### 1.3 Ergebnis-Kurzfassung

| Metrik | Wert |
|--------|------|
| Ausgefuehrte Testcases | [Anzahl] |
| MITRE Techniken getestet | [Anzahl] / 188 |
| SIEM Use Cases geprueft | [Anzahl] / 111 |
| PASSED (erkannt) | [Anzahl] |
| FAILED (nicht erkannt) | [Anzahl] |
| Compliance Rate | [X]% |
| Kill Chains erkannt | [Anzahl] |

---

## 2. Methodik

### 2.1 Testframework

- **Adversary Emulation**: MITRE Caldera v5.0 mit Batch Planner
- **SIEM-Validierung**: Splunk Enterprise mit 113 Saved Searches
- **Bedrohungsmodelle**: 16 Banking-spezifische Adversary-Profile
- **Automatisierung**: 3x taegliche Ausfuehrung via Cron

### 2.2 Bedrohungslandschaft

Die Testprofile basieren auf der aktuellen Banking Threat Landscape:
- RansomHub / LockBit / Akira (Ransomware)
- Lazarus Group / APT43 (Staatliche Akteure)
- Scattered Spider / Volt Typhoon (Living-off-the-Land)
- Insider Threats

### 2.3 MITRE ATT&CK Abdeckung

| Taktik | Techniken | Use Cases | Abdeckung |
|--------|-----------|-----------|-----------|
| Credential Access | [N] | UC-001..008 | [X]% |
| Privilege Escalation | [N] | UC-020..024 | [X]% |
| Lateral Movement | [N] | UC-030..034 | [X]% |
| Defense Evasion | [N] | UC-040..059 | [X]% |
| Discovery | [N] | UC-060..079 | [X]% |
| Execution | [N] | UC-080..087 | [X]% |
| Persistence | [N] | UC-090..098 | [X]% |
| Exfiltration | [N] | UC-100..106 | [X]% |
| Collection | [N] | UC-110..119 | [X]% |
| C2 | [N] | UC-120..125 | [X]% |
| Impact | [N] | UC-130..139 | [X]% |
| Initial Access | [N] | UC-140..142 | [X]% |

---

## 3. Detaillierte Ergebnisse

### 3.1 Erkannte Angriffe (PASSED)

| UseCase ID | Name | Schweregrad | Trigger-Anzahl | DORA Art. |
|-----------|------|-------------|----------------|-----------|
| UC-BANK-001 | Credential Dumping | CRITICAL | [N] | Art. 25 |
| ... | ... | ... | ... | ... |

### 3.2 Nicht erkannte Angriffe (FAILED)

| UseCase ID | Name | Schweregrad | Fehlende Erkennung | Massnahme | Frist |
|-----------|------|-------------|-------------------|-----------|-------|
| [ID] | [Name] | [Sev] | [Beschreibung] | [Massnahme] | [Datum] |

### 3.3 Kill Chain Korrelationen

| Zeitpunkt | Host | Erkannte Kette | Beteiligte UseCases | Bewertung |
|-----------|------|----------------|---------------------|-----------|
| [Timestamp] | [Host] | [Kette] | [UC-IDs] | [Bewertung] |

---

## 4. DORA Art. 26 TLPT-Konformitaetserklaerung

### 4.1 Anforderungen an TLPT

| DORA Art. 26 Absatz | Anforderung | Erfuellt | Nachweis |
|---------------------|-------------|----------|---------|
| Abs. 1 | Bedrohungsgeleitete Tests | Ja/Nein | Adversary-Profile basierend auf TI |
| Abs. 2 | Live-Produktionssysteme | Ja/Nein | [Testumgebung beschreiben] |
| Abs. 3 | Alle 3 Jahre | Ja/Nein | Framework laeuft taeglich |
| Abs. 4 | Externe Tester | Ja/Nein | [Intern/Extern dokumentieren] |
| Abs. 5 | Berichterstattung | Ja/Nein | Dieser ITSO-Bericht |
| Abs. 6 | Massnahmenplan | Ja/Nein | Siehe Abschnitt 5 |
| Abs. 7 | BaFin-Mitteilung | Ja/Nein | [Datum der Mitteilung] |
| Abs. 8 | Zusammenfassung an BaFin | Ja/Nein | [Referenz] |

### 4.2 BaFin-Meldepflichten

| Meldepflicht | Relevanz | Status |
|-------------|----------|--------|
| DORA Art. 19 Abs. 1 (schwerwiegend) | [Ja/Nein] | [Gemeldet am / Nicht erforderlich] |
| DORA Art. 19 Abs. 4 (freiwillig) | [Ja/Nein] | [Status] |
| DSGVO Art. 33 (Datenschutz) | [Ja/Nein] | [Status] |
| BaFin MaRisk AT 4.3.2 (wesentlich) | [Ja/Nein] | [Status] |

---

## 5. Massnahmenplan (Remediation)

### 5.1 Sofortmassnahmen (< 7 Tage)

| Nr. | Massnahme | UseCase | Verantwortlich | Frist | Status |
|-----|-----------|---------|---------------|-------|--------|
| 1 | [Massnahme] | [UC-ID] | [Rolle] | [Datum] | [Offen/InArbeit/Erledigt] |

### 5.2 Kurzfristige Massnahmen (< 30 Tage)

| Nr. | Massnahme | UseCase | Verantwortlich | Frist | Status |
|-----|-----------|---------|---------------|-------|--------|
| 1 | [Massnahme] | [UC-ID] | [Rolle] | [Datum] | [Status] |

### 5.3 Mittelfristige Massnahmen (< 90 Tage)

| Nr. | Massnahme | UseCase | Verantwortlich | Frist | Status |
|-----|-----------|---------|---------------|-------|--------|
| 1 | [Massnahme] | [UC-ID] | [Rolle] | [Datum] | [Status] |

---

## 6. Empfehlungen

### 6.1 Technische Empfehlungen

1. **SIEM-Regeloptimierung**: [Anzahl] Use Cases muessen nachgeschaerft werden
2. **EDR-Integration**: Empfehlung zur Integration von EDR-Daten in SIEM
3. **Netzwerksegmentierung**: Lateral Movement Tests zeigen [Ergebnis]
4. **Logging**: Log-Quellen fuer [Taktik] erweitern

### 6.2 Organisatorische Empfehlungen

1. **SOC-Prozesse**: Eskalationsverfahren fuer Kill-Chain-Alerts etablieren
2. **Schulung**: SOC-Team auf MITRE ATT&CK Erkennung schulen
3. **Testfrequenz**: [Empfehlung zur Frequenz]

---

## 7. Freigabe

| Rolle | Name | Datum | Unterschrift |
|-------|------|-------|-------------|
| ITSO | [Name] | [Datum] | ____________ |
| CISO | [Name] | [Datum] | ____________ |
| IT-Leitung | [Name] | [Datum] | ____________ |
| Vorstand (IT) | [Name] | [Datum] | ____________ |

---

## Anhang

### A. UseCase-Katalog

Siehe [USECASE_CATALOG.md](USECASE_CATALOG.md)

### B. Compliance-Status JSON

Datei: `/opt/caldera-splunk/compliance-status.json`

### C. Splunk Dashboard Screenshots

[Screenshots manuell einfuegen oder exportieren]

### D. Glossar

| Begriff | Definition |
|---------|-----------|
| DORA | Digital Operational Resilience Act (EU 2022/2554) |
| TLPT | Threat-Led Penetration Testing |
| TIBER-EU | Threat Intelligence-Based Ethical Red Teaming |
| MITRE ATT&CK | Adversarial Tactics, Techniques, and Common Knowledge |
| SIEM | Security Information and Event Management |
| SOC | Security Operations Center |
| CSIRT | Computer Security Incident Response Team |
| ITSO | IT-Sicherheitsbeauftragter |
| BaFin | Bundesanstalt fuer Finanzdienstleistungsaufsicht |
| EZB | Europaeische Zentralbank |
| MaRisk | Mindestanforderungen an das Risikomanagement |
| BAIT | Bankaufsichtliche Anforderungen an die IT |

---

*Dieses Dokument unterliegt der bankinternen Vertraulichkeit. Weitergabe nur an autorisierte Stellen.*
