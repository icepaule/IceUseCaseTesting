---
layout: default
title: Home
---

# TIBER/DORA Bank Purple Team Framework

> Automatisierte Adversary-Emulation und SIEM-UseCase-Validierung für mittelständische Banken

![Architecture](docs/images/01_architecture_overview.png)

---

## Was ist dieses Projekt?

Dieses Framework stellt ein vollständiges **Purple Team Testing Setup** bereit, mit dem Banken ihre SIEM-Erkennung gegen aktuelle Bedrohungen (2025/2026) validieren können.

| Komponente | Umfang |
|-----------|--------|
| Caldera Adversary-Profile | 6 Banking-Szenarien, 111 Abilities |
| SIEM Use Cases | 15 Splunk Saved Searches |
| MITRE ATT&CK Coverage | 63 Techniken, 11 Taktiken |
| Regulatorik | DORA, TIBER-EU, MaRisk, BAIT, DSGVO |

---

## Dokumentation

- [**Betriebshandbuch**](docs/BETRIEBSHANDBUCH.md) - Vollständige Installations- und Betriebsanleitung
- [**Adversary Profile**](docs/ADVERSARY_PROFILES.md) - 6 Banking-Bedrohungsszenarien im Detail
- [**SIEM Use Cases**](docs/SIEM_USECASES.md) - 15 Korrelationsregeln mit DORA-Mapping
- [**Architektur**](docs/ARCHITEKTUR.md) - Systemarchitektur und Datenfluss

---

## Bedrohungsszenarien

![Adversary Profiles](docs/images/02_adversary_profiles.png)

| # | Profil | Bedrohung | Abilities | Schwerpunkt |
|---|--------|-----------|-----------|-------------|
| 1 | Ransomware Chain | RansomHub/LockBit/Akira | 21 | Vollständige Kill Chain |
| 2 | APT Espionage | Lazarus/APT43 | 23 | Stille Exfiltration |
| 3 | Insider Threat | Böswilliger Insider | 15 | Datendiebstahl |
| 4 | Lateral Movement | Scattered Spider | 20 | Segmentierung testen |
| 5 | Defense Evasion | Advanced Evasion | 16 | SIEM-Erkennung |
| 6 | Data Exfiltration | Multi-Channel | 16 | DLP-Kontrollen |

---

## SIEM Use Cases

![SIEM Use Cases](docs/images/03_siem_usecases.png)

**15 Use Cases** mit Schweregrad-Verteilung:
- **8x CRITICAL**: Credential Dumping, Priv Esc, Lateral Movement, Exfiltration, Evasion, Log Tampering, C2, Ransomware
- **4x HIGH**: Reconnaissance, Execution, Persistence, Data Access
- **1x MEDIUM**: Crypto Mining
- **1x META**: Kill Chain Correlation (korreliert alle anderen)

---

## Datenfluss

![Data Flow](docs/images/04_data_flow.png)

---

## Dashboard

![Dashboard Mockup](docs/images/05_dashboard_mockup.png)

---

## MITRE ATT&CK Abdeckung

![MITRE Coverage](docs/images/07_mitre_coverage.png)

---

## Quick Start

```bash
git clone https://github.com/icepaule/IceUseCaseTesting.git
cp examples/config.env.example .env
# → Eigene Werte eintragen
cp caldera/adversaries/*.yml /opt/caldera/data/adversaries/
source .env && ./scripts/install-splunk-app.sh
./scripts/run-bank-adversaries.sh
./scripts/publish-to-splunk.sh
```

Details: [Betriebshandbuch](docs/BETRIEBSHANDBUCH.md)

---

## Regulatorischer Rahmen

| Regulierung | Artikel | Abdeckung |
|-------------|---------|-----------|
| **DORA** | Art. 25-27 | Alle Use Cases |
| **TIBER-EU** | Active Phase | Alle Adversary-Profile |
| **MaRisk** | AT 7.2 | UC-009 (Logging) |
| **BAIT** | Abschnitt 5 | Alle Use Cases |
| **DSGVO** | Art. 33 | UC-006 (Exfiltration) |

---

## Quellen

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE CTID - CRI Profile Mapping](https://ctid.mitre.org/blog/2025/06/16/threat-informed-defense-for-the-financial-sector/)
- [TIBER-EU Framework (ECB)](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html)
- [DORA TLPT RTS](https://tiber.info/blog/2025/06/18/the-dora-threat-led-penetration-testing-rts-has-been-published/)
- [PT Security Financial Forecast 2025-2026](https://global.ptsecurity.com/en/research/analytics/cyberthreats-to-the-financial-sector--forecast-for-2025-2026/)
- [Flashpoint Financial Threat Actors](https://flashpoint.io/blog/top-threat-actor-groups-targeting-financial-sector/)

---

*Dieses Projekt dient ausschließlich zu Bildungs- und Testzwecken in autorisierten Umgebungen.*
