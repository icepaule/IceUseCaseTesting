#!/usr/bin/env python3
"""
Generates architecture diagrams and visual documentation for the
TIBER/DORA Bank Purple Team Testing project.
Uses Pillow to create professional diagrams as PNG images.
"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "images")
os.makedirs(OUT_DIR, exist_ok=True)

# Use default font (monospace-like)
try:
    FONT_LARGE = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 22)
    FONT_MED = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
    FONT_SMALL = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 13)
    FONT_TINY = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
except:
    FONT_LARGE = ImageFont.load_default()
    FONT_MED = ImageFont.load_default()
    FONT_SMALL = ImageFont.load_default()
    FONT_TINY = ImageFont.load_default()

# Color scheme
C_BG = "#1a1a2e"
C_PANEL = "#16213e"
C_BORDER = "#0f3460"
C_ACCENT = "#e94560"
C_GREEN = "#53a051"
C_YELLOW = "#f8be34"
C_ORANGE = "#f1813f"
C_RED = "#dc4e41"
C_BLUE = "#0877a6"
C_WHITE = "#e0e0e0"
C_GRAY = "#888888"
C_DARK = "#0a0a1a"

def draw_rounded_rect(draw, xy, radius, fill, outline=None, width=1):
    x0, y0, x1, y1 = xy
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)

def draw_box(draw, x, y, w, h, label, sublabel="", color=C_BORDER, fill=C_PANEL):
    draw_rounded_rect(draw, (x, y, x+w, y+h), 8, fill=fill, outline=color, width=2)
    draw.text((x+w//2, y+12), label, fill=C_WHITE, font=FONT_MED, anchor="mt")
    if sublabel:
        draw.text((x+w//2, y+32), sublabel, fill=C_GRAY, font=FONT_TINY, anchor="mt")

def draw_arrow(draw, x1, y1, x2, y2, color=C_ACCENT, label=""):
    draw.line([(x1, y1), (x2, y2)], fill=color, width=2)
    # Arrowhead
    if y2 > y1:  # down
        draw.polygon([(x2-6, y2-8), (x2+6, y2-8), (x2, y2)], fill=color)
    elif x2 > x1:  # right
        draw.polygon([(x2-8, y2-6), (x2-8, y2+6), (x2, y2)], fill=color)
    if label:
        mx, my = (x1+x2)//2, (y1+y2)//2
        draw.text((mx+5, my-8), label, fill=C_YELLOW, font=FONT_TINY)


def create_architecture_diagram():
    """01 - Overall Architecture"""
    img = Image.new("RGB", (1200, 800), C_BG)
    draw = ImageDraw.Draw(img)

    draw.text((600, 25), "TIBER/DORA Bank Purple Team - Systemarchitektur", fill=C_WHITE, font=FONT_LARGE, anchor="mt")
    draw.text((600, 52), "Caldera Adversary Emulation + Splunk SIEM Integration", fill=C_GRAY, font=FONT_SMALL, anchor="mt")

    # Caldera Server
    draw_rounded_rect(draw, (30, 85, 370, 350), 12, fill=C_DARK, outline=C_ACCENT, width=2)
    draw.text((200, 95), "CALDERA SERVER", fill=C_ACCENT, font=FONT_MED, anchor="mt")
    draw_box(draw, 50, 125, 140, 50, "6 Adversary", "Bank-Profile", C_RED)
    draw_box(draw, 210, 125, 140, 50, "162+ Abilities", "Stockpile+Atomic", C_ORANGE)
    draw_box(draw, 50, 190, 140, 50, "Sandcat Agent", "Go-based RAT", C_BLUE)
    draw_box(draw, 210, 190, 140, 50, "16 Plugins", "Full Stack", C_BLUE)
    draw_box(draw, 50, 255, 300, 50, "REST API :8888", "Operations, Agents, Adversaries", C_BORDER)
    draw_box(draw, 50, 310, 140, 30, "TCP :7010", color=C_GRAY)
    draw_box(draw, 210, 310, 140, 30, "WS :7011/UDP", color=C_GRAY)

    # Target Systems
    draw_rounded_rect(draw, (30, 380, 370, 530), 12, fill=C_DARK, outline=C_GREEN, width=2)
    draw.text((200, 390), "TARGET SYSTEMS", fill=C_GREEN, font=FONT_MED, anchor="mt")
    draw_box(draw, 50, 420, 140, 45, "Windows", "Sandcat Agent", C_GREEN)
    draw_box(draw, 210, 420, 140, 45, "Linux", "Sandcat Agent", C_GREEN)
    draw_box(draw, 130, 475, 140, 45, "Bank-Netz", "10.99.0.0/24", C_GREEN)

    draw_arrow(draw, 200, 350, 200, 380, C_GREEN, "C2")

    # Publisher / Enrichment
    draw_rounded_rect(draw, (420, 85, 780, 280), 12, fill=C_DARK, outline=C_YELLOW, width=2)
    draw.text((600, 95), "DATA PUBLISHER", fill=C_YELLOW, font=FONT_MED, anchor="mt")
    draw_box(draw, 440, 125, 150, 45, "publish-to-", "splunk.sh", C_YELLOW)
    draw_box(draw, 610, 125, 150, 45, "MITRE Lookup", "79 Techniques", C_ORANGE)
    draw_box(draw, 440, 185, 150, 45, "Base64 Decode", "Command Parse", C_BLUE)
    draw_box(draw, 610, 185, 150, 45, "Artifact Class.", "8 Kategorien", C_BLUE)
    draw_box(draw, 440, 240, 320, 30, "Enriched JSON → Splunk HEC :8088", color=C_YELLOW)

    draw_arrow(draw, 370, 280, 420, 180, C_YELLOW, "API")

    # Splunk
    draw_rounded_rect(draw, (830, 85, 1170, 450), 12, fill=C_DARK, outline=C_BLUE, width=2)
    draw.text((1000, 95), "SPLUNK SIEM", fill=C_BLUE, font=FONT_MED, anchor="mt")
    draw.text((1000, 115), "<SPLUNK_HOST>", fill=C_GRAY, font=FONT_TINY, anchor="mt")
    draw_box(draw, 850, 135, 140, 40, "idx: caldera", "Raw Events", C_BLUE)
    draw_box(draw, 1010, 135, 140, 40, "idx: siem_sum", "Correlated", C_BLUE)
    draw_box(draw, 850, 190, 300, 40, "15 SIEM Use Cases (Saved Searches)", color=C_RED)
    draw_box(draw, 850, 245, 300, 40, "Kill Chain Correlation (UC-015)", color=C_RED)
    draw_box(draw, 850, 300, 300, 40, "Dashboard: Purple Team Overview", color=C_GREEN)
    draw_box(draw, 850, 355, 145, 40, "MITRE Map", "Lookup CSV", C_ORANGE)
    draw_box(draw, 1005, 355, 145, 40, "DORA/TIBER", "Compliance", C_ORANGE)
    draw_box(draw, 850, 405, 300, 35, "Alerts → SOC / CSIRT", color=C_ACCENT)

    draw_arrow(draw, 780, 255, 830, 160, C_BLUE, "HEC")

    # Orchestrator
    draw_rounded_rect(draw, (420, 320, 780, 530), 12, fill=C_DARK, outline=C_GREEN, width=2)
    draw.text((600, 330), "ORCHESTRATOR", fill=C_GREEN, font=FONT_MED, anchor="mt")
    draw_box(draw, 440, 360, 320, 40, "run-bank-adversaries.sh", color=C_GREEN)

    profiles = [
        ("1. Defense Evasion", C_ORANGE), ("2. Lateral Movement", C_RED),
        ("3. APT Espionage", C_RED), ("4. Insider Threat", C_YELLOW),
        ("5. Data Exfiltration", C_RED), ("6. Ransomware", C_ACCENT)
    ]
    for i, (name, color) in enumerate(profiles):
        x = 440 + (i % 2) * 165
        y = 410 + (i // 2) * 38
        draw_box(draw, x, y, 155, 32, name, color=color)

    draw_arrow(draw, 500, 320, 300, 305, C_GREEN, "Caldera API")
    draw_arrow(draw, 700, 320, 780, 270, C_YELLOW, "→ Publish")

    # Legend
    draw.text((30, 560), "Legende:", fill=C_WHITE, font=FONT_MED)
    items = [
        (C_ACCENT, "Caldera Core"), (C_GREEN, "Agents/Targets"),
        (C_YELLOW, "Data Pipeline"), (C_BLUE, "Splunk SIEM"),
        (C_RED, "Critical Alerts"), (C_ORANGE, "MITRE ATT&CK")
    ]
    for i, (color, label) in enumerate(items):
        x = 30 + (i % 3) * 200
        y = 590 + (i // 3) * 25
        draw.rectangle((x, y, x+15, y+15), fill=color)
        draw.text((x+22, y), label, fill=C_WHITE, font=FONT_SMALL)

    # Regulatory badges
    draw.text((30, 650), "Regulatorik:", fill=C_WHITE, font=FONT_MED)
    badges = ["DORA Art.25-27", "TIBER-EU 2025", "MaRisk AT 7.2", "BAIT", "DSGVO Art.33"]
    for i, badge in enumerate(badges):
        x = 30 + i * 160
        draw_rounded_rect(draw, (x, 680, x+150, 710), 5, fill=C_BORDER, outline=C_ACCENT)
        draw.text((x+75, 695), badge, fill=C_WHITE, font=FONT_TINY, anchor="mm")

    # Blurred sensitive info note
    draw_rounded_rect(draw, (30, 730, 1170, 780), 5, fill="#2a1a1a", outline=C_RED)
    draw.text((600, 755), "Sensible Daten (API-Keys, Passwoerter, IPs) sind in dieser Dokumentation anonymisiert/entfernt",
              fill=C_RED, font=FONT_SMALL, anchor="mm")

    img.save(os.path.join(OUT_DIR, "01_architecture_overview.png"), quality=95)
    print("01_architecture_overview.png created")


def create_adversary_profiles_diagram():
    """02 - Adversary Profiles with Kill Chain mapping"""
    img = Image.new("RGB", (1200, 900), C_BG)
    draw = ImageDraw.Draw(img)

    draw.text((600, 25), "Banking Adversary Profile - MITRE ATT&CK Kill Chain Mapping", fill=C_WHITE, font=FONT_LARGE, anchor="mt")

    # Kill chain header
    tactics = ["Discovery", "Cred.Access", "Priv.Esc", "Def.Evasion", "Lat.Movement", "Execution", "Persistence", "Collection", "Exfiltration", "Impact"]
    for i, tactic in enumerate(tactics):
        x = 30 + i * 117
        color = [C_BLUE, C_RED, C_RED, C_ORANGE, C_RED, C_YELLOW, C_ORANGE, C_YELLOW, C_RED, C_ACCENT][i]
        draw_rounded_rect(draw, (x, 65, x+112, 95), 5, fill=color, outline=color)
        draw.text((x+56, 80), tactic, fill=C_WHITE, font=FONT_TINY, anchor="mm")

    profiles = [
        ("TIBER-Bank-Ransomware-Chain", "RansomHub / LockBit / Akira",
         [1,1,0,1,1,0,0,1,0,1], C_ACCENT, "21 Abilities | T1018→T1499"),
        ("TIBER-Bank-APT-Espionage", "Lazarus / APT43 (Nordkorea)",
         [1,1,0,1,0,0,1,1,1,0], C_RED, "23 Abilities | T1497→T1041"),
        ("TIBER-Bank-Insider-Threat", "Boesartiger Insider",
         [1,0,0,0,0,0,0,1,1,0], C_YELLOW, "15 Abilities | T1087→T1048"),
        ("TIBER-Bank-Lateral-Movement", "Scattered Spider / Volt Typhoon",
         [1,1,1,0,1,1,0,0,0,0], C_ORANGE, "20 Abilities | T1018→T1569"),
        ("TIBER-Bank-Defense-Evasion", "Advanced Evasion Testing",
         [1,0,0,1,0,1,0,0,0,0], C_BLUE, "16 Abilities | T1497→T1059"),
        ("TIBER-Bank-Data-Exfiltration", "Multi-Channel Data Theft",
         [0,0,0,0,0,0,0,1,1,0], C_GREEN, "16 Abilities | T1005→T1029"),
    ]

    for j, (name, threat, phases, color, detail) in enumerate(profiles):
        y = 115 + j * 125
        # Profile box
        draw_rounded_rect(draw, (30, y, 1170, y+115), 8, fill=C_DARK, outline=color, width=2)
        draw.text((45, y+8), name, fill=color, font=FONT_MED)
        draw.text((45, y+30), f"Bedrohungsmodell: {threat}", fill=C_GRAY, font=FONT_SMALL)
        draw.text((45, y+48), detail, fill=C_WHITE, font=FONT_SMALL)

        # Phase indicators
        for i, active in enumerate(phases):
            x = 30 + i * 117
            cy = y + 85
            if active:
                draw_rounded_rect(draw, (x+10, cy-12, x+102, cy+12), 5, fill=color, outline=color)
                draw.text((x+56, cy), "AKTIV", fill=C_WHITE, font=FONT_TINY, anchor="mm")
            else:
                draw_rounded_rect(draw, (x+10, cy-12, x+102, cy+12), 5, fill=C_DARK, outline=C_GRAY)
                draw.text((x+56, cy), "-", fill=C_GRAY, font=FONT_TINY, anchor="mm")

    # Footer
    draw.text((600, 870), "Gesamt: 111 Abilities | 63 MITRE Techniken | 11 Taktiken | 6 Adversary-Profile",
              fill=C_WHITE, font=FONT_MED, anchor="mm")

    img.save(os.path.join(OUT_DIR, "02_adversary_profiles.png"), quality=95)
    print("02_adversary_profiles.png created")


def create_siem_usecases_diagram():
    """03 - SIEM Use Cases Overview"""
    img = Image.new("RGB", (1200, 950), C_BG)
    draw = ImageDraw.Draw(img)

    draw.text((600, 25), "SIEM Use Cases - Banking Purple Team", fill=C_WHITE, font=FONT_LARGE, anchor="mt")
    draw.text((600, 52), "15 Korrelationsregeln mit DORA/TIBER-EU Mapping", fill=C_GRAY, font=FONT_SMALL, anchor="mt")

    usecases = [
        ("UC-BANK-001", "Credential Dumping Detection", "CRITICAL", "T1003,T1040,T1552", "DORA Art.25", C_RED),
        ("UC-BANK-002", "Privilege Escalation Detection", "CRITICAL", "T1548,T1134,T1574", "DORA Art.25", C_RED),
        ("UC-BANK-003", "Network Reconnaissance Detection", "HIGH", "T1016-T1087,T1482", "DORA Art.25", C_ORANGE),
        ("UC-BANK-004", "Lateral Movement Detection", "CRITICAL", "T1021,T1570", "DORA Art.25", C_RED),
        ("UC-BANK-005", "Suspicious Execution Detection", "HIGH", "T1059,T1047,T1569", "DORA Art.25", C_ORANGE),
        ("UC-BANK-006", "Data Exfiltration Detection", "CRITICAL", "T1041,T1048,T1567", "DORA Art.19/25", C_RED),
        ("UC-BANK-007", "Defense Evasion Detection", "CRITICAL", "T1562,T1055,T1497", "DORA Art.25", C_RED),
        ("UC-BANK-008", "Persistence Detection", "HIGH", "T1053,T1136,T1543", "DORA Art.25", C_ORANGE),
        ("UC-BANK-009", "Log Tampering Detection", "CRITICAL", "T1070", "DORA Art.12", C_RED),
        ("UC-BANK-010", "Sensitive Data Access Detection", "HIGH", "T1005,T1074,T1119", "DORA Art.25", C_ORANGE),
        ("UC-BANK-011", "C2 Communication Detection", "CRITICAL", "T1071,T1105", "DORA Art.25", C_RED),
        ("UC-BANK-012", "Ransomware Detection", "CRITICAL", "T1486,T1489,T1491", "DORA Art.19", C_RED),
        ("UC-BANK-013", "Crypto Mining Detection", "MEDIUM", "T1496", "DORA Art.25", C_YELLOW),
        ("UC-BANK-014", "System Impact Detection", "CRITICAL", "T1499,T1565", "DORA Art.25", C_RED),
        ("UC-BANK-015", "Kill Chain Correlation", "CRITICAL", "Meta-Korrelation", "DORA Art.25/26", C_ACCENT),
    ]

    # Header row
    draw_rounded_rect(draw, (30, 75, 1170, 105), 5, fill=C_BORDER, outline=C_BORDER)
    headers = [("UseCase ID", 50), ("Name", 200), ("Severity", 470), ("MITRE Techniques", 600), ("DORA", 850), ("Frequenz", 1000)]
    for label, x in headers:
        draw.text((x, 90), label, fill=C_WHITE, font=FONT_MED, anchor="lm")

    for i, (uc_id, name, severity, mitre, dora, color) in enumerate(usecases):
        y = 115 + i * 52
        bg = C_DARK if i % 2 == 0 else C_PANEL
        draw_rounded_rect(draw, (30, y, 1170, y+48), 3, fill=bg, outline=C_BORDER)

        # Severity badge
        sev_color = {
            "CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW
        }.get(severity, C_GRAY)

        draw.text((50, y+24), uc_id, fill=color, font=FONT_MED, anchor="lm")
        draw.text((200, y+24), name, fill=C_WHITE, font=FONT_SMALL, anchor="lm")
        draw_rounded_rect(draw, (470, y+8, 560, y+40), 4, fill=sev_color)
        draw.text((515, y+24), severity, fill=C_WHITE, font=FONT_TINY, anchor="mm")
        draw.text((600, y+24), mitre, fill=C_GRAY, font=FONT_TINY, anchor="lm")
        draw.text((850, y+24), dora, fill=C_YELLOW, font=FONT_TINY, anchor="lm")
        draw.text((1000, y+24), "*/5 * * * *", fill=C_GRAY, font=FONT_TINY, anchor="lm")

    # Summary footer
    y_foot = 905
    draw_rounded_rect(draw, (30, y_foot, 1170, y_foot+35), 5, fill=C_BORDER)
    draw.text((600, y_foot+17), "8x CRITICAL | 4x HIGH | 1x MEDIUM | 1x Meta-Korrelation | Summary-Index: siem_summary",
              fill=C_WHITE, font=FONT_SMALL, anchor="mm")

    img.save(os.path.join(OUT_DIR, "03_siem_usecases.png"), quality=95)
    print("03_siem_usecases.png created")


def create_data_flow_diagram():
    """04 - Data Flow / Pipeline"""
    img = Image.new("RGB", (1200, 700), C_BG)
    draw = ImageDraw.Draw(img)

    draw.text((600, 25), "Datenfluss: Caldera → Enrichment → Splunk SIEM", fill=C_WHITE, font=FONT_LARGE, anchor="mt")

    # Step 1: Caldera API
    draw_rounded_rect(draw, (30, 80, 250, 280), 10, fill=C_DARK, outline=C_ACCENT, width=2)
    draw.text((140, 95), "1. Caldera API", fill=C_ACCENT, font=FONT_MED, anchor="mt")
    entries = ["/api/v2/operations", "/api/v2/agents", "chain[] commands", "ability metadata", "technique_id, tactic"]
    for i, e in enumerate(entries):
        draw.text((50, 125+i*28), f"• {e}", fill=C_WHITE, font=FONT_SMALL)

    draw_arrow(draw, 250, 180, 310, 180, C_YELLOW)

    # Step 2: Publisher
    draw_rounded_rect(draw, (310, 80, 560, 280), 10, fill=C_DARK, outline=C_YELLOW, width=2)
    draw.text((435, 95), "2. Publisher", fill=C_YELLOW, font=FONT_MED, anchor="mt")
    entries = ["Base64-Erkennung", "Command-Dekodierung", "MITRE Lookup (CSV)", "Artefakt-Klassifikation", "UseCase-Zuordnung", "JSON Enrichment"]
    for i, e in enumerate(entries):
        draw.text((325, 120+i*25), f"→ {e}", fill=C_WHITE, font=FONT_SMALL)

    draw_arrow(draw, 560, 180, 620, 180, C_BLUE)

    # Step 3: Splunk HEC
    draw_rounded_rect(draw, (620, 80, 850, 280), 10, fill=C_DARK, outline=C_BLUE, width=2)
    draw.text((735, 95), "3. Splunk HEC", fill=C_BLUE, font=FONT_MED, anchor="mt")
    entries = ["HTTP :8088", "caldera:command:enriched", "caldera:agent", "caldera:operation", "→ Index: caldera"]
    for i, e in enumerate(entries):
        draw.text((635, 120+i*28), f"• {e}", fill=C_WHITE, font=FONT_SMALL)

    draw_arrow(draw, 735, 280, 735, 330, C_RED)

    # Step 4: SIEM Correlation
    draw_rounded_rect(draw, (500, 330, 970, 520), 10, fill=C_DARK, outline=C_RED, width=2)
    draw.text((735, 345), "4. SIEM Korrelation (alle 5 Min)", fill=C_RED, font=FONT_MED, anchor="mt")

    draw_box(draw, 520, 375, 210, 40, "15 Saved Searches", "Pattern Matching", C_RED)
    draw_box(draw, 740, 375, 210, 40, "MITRE Lookup Join", "Technique→UseCase", C_ORANGE)
    draw_box(draw, 520, 425, 210, 40, "Artifact Classification", "8 Kategorien", C_YELLOW)
    draw_box(draw, 740, 425, 210, 40, "Kill Chain Corr.", "≥3 UC in 30min", C_ACCENT)
    draw_box(draw, 620, 475, 220, 35, "→ collect index=siem_summary", color=C_GREEN)

    draw_arrow(draw, 735, 520, 735, 560, C_GREEN)

    # Step 5: Dashboard
    draw_rounded_rect(draw, (400, 560, 1070, 680), 10, fill=C_DARK, outline=C_GREEN, width=2)
    draw.text((735, 575), "5. Dashboard & Alerting", fill=C_GREEN, font=FONT_MED, anchor="mt")

    panels = ["KPI Overview", "Testcase-Matrix", "MITRE Heatmap", "Kill Chain Timeline", "DORA Compliance", "Erkennungsluecken"]
    for i, panel in enumerate(panels):
        x = 420 + (i % 3) * 215
        y = 600 + (i // 3) * 35
        draw_rounded_rect(draw, (x, y, x+200, y+28), 4, fill=C_BORDER)
        draw.text((x+100, y+14), panel, fill=C_WHITE, font=FONT_TINY, anchor="mm")

    # Enriched fields
    draw_rounded_rect(draw, (30, 330, 450, 680), 10, fill=C_DARK, outline=C_YELLOW, width=2)
    draw.text((240, 345), "Enriched Event Felder", fill=C_YELLOW, font=FONT_MED, anchor="mt")
    fields = [
        "operation_name", "ability_name", "technique_id",
        "technique_name", "tactic", "command_decoded",
        "artifact_type", "siem_usecase_id", "siem_usecase_name",
        "severity", "bank_relevance", "dora_article",
        "correlation_key", "command_keywords"
    ]
    for i, f in enumerate(fields):
        y = 375 + i * 21
        color = C_GREEN if "usecase" in f or "severity" in f else C_WHITE
        draw.text((50, y), f"  {f}", fill=color, font=FONT_SMALL)

    img.save(os.path.join(OUT_DIR, "04_data_flow.png"), quality=95)
    print("04_data_flow.png created")


def create_dashboard_mockup():
    """05 - Dashboard Mockup"""
    img = Image.new("RGB", (1400, 900), "#111111")
    draw = ImageDraw.Draw(img)

    # Splunk-style title bar
    draw_rounded_rect(draw, (0, 0, 1400, 50), 0, fill="#171d21")
    draw.text((20, 25), "splunk>", fill="#65a637", font=FONT_LARGE, anchor="lm")
    draw.text((140, 25), "enterprise", fill="#999999", font=FONT_MED, anchor="lm")
    draw.text((700, 25), "TIBER/DORA Bank Purple Team - Caldera Testauswertung", fill=C_WHITE, font=FONT_MED, anchor="mm")

    # Blur bar for sensitive info
    draw_rounded_rect(draw, (1050, 10, 1380, 40), 5, fill="#333333")
    draw.text((1215, 25), "■■■■■■@■■■■.bank.local", fill="#555555", font=FONT_SMALL, anchor="mm")

    # KPI Row
    kpis = [
        ("Testcases", "6", C_BLUE), ("Artefakte", "111", C_GREEN),
        ("SIEM Triggered", "12/15", C_YELLOW), ("Kill Chains", "3", C_RED),
        ("MITRE Techniken", "63", C_ORANGE)
    ]
    for i, (label, value, color) in enumerate(kpis):
        x = 20 + i * 275
        draw_rounded_rect(draw, (x, 65, x+260, 145), 8, fill=C_DARK, outline=C_BORDER)
        draw.text((x+130, 95), value, fill=color, font=FONT_LARGE, anchor="mm")
        draw.text((x+130, 125), label, fill=C_GRAY, font=FONT_SMALL, anchor="mm")

    # Table mock
    draw_rounded_rect(draw, (20, 160, 1380, 450), 8, fill=C_DARK, outline=C_BORDER)
    draw.text((40, 175), "Testcases mit MITRE ATT&CK und SIEM-UseCase Zuordnung", fill=C_WHITE, font=FONT_MED)

    # Header
    draw_rounded_rect(draw, (30, 200, 1370, 228), 3, fill=C_BORDER)
    cols = [("Testcase/Operation", 40), ("Artefakte", 320), ("MITRE IDs", 400), ("Taktiken", 620), ("SIEM UseCases", 800), ("Erkennung", 1000), ("Status", 1150)]
    for label, x in cols:
        draw.text((x, 214), label, fill=C_WHITE, font=FONT_TINY, anchor="lm")

    rows = [
        ("Bank-Ransomware-Chain", "21", "T1018,T1003,T1021...", "disc,cred,lat,imp", "001,004,006,012", "80%", "TEILWEISE", C_YELLOW),
        ("Bank-APT-Espionage", "23", "T1497,T1003,T1053...", "disc,cred,pers,exf", "001,003,006,008", "90%", "TEILWEISE", C_YELLOW),
        ("Bank-Insider-Threat", "15", "T1087,T1005,T1048...", "disc,coll,exfil", "003,006,010", "100%", "VOLLSTAENDIG", C_GREEN),
        ("Bank-Lateral-Movement", "20", "T1018,T1548,T1021...", "disc,cred,priv,lat", "001,002,003,004", "75%", "TEILWEISE", C_YELLOW),
        ("Bank-Defense-Evasion", "16", "T1497,T1562,T1055...", "disc,def-ev,exec", "005,007,009", "85%", "TEILWEISE", C_YELLOW),
        ("Bank-Data-Exfiltration", "16", "T1005,T1074,T1567...", "coll,exfil", "006,010", "100%", "VOLLSTAENDIG", C_GREEN),
    ]
    for i, (name, arts, mitre, tact, ucs, pct, status, color) in enumerate(rows):
        y = 235 + i * 33
        bg = C_DARK if i % 2 == 0 else "#0d1117"
        draw.rectangle((30, y, 1370, y+30), fill=bg)
        draw.text((40, y+15), name, fill=C_WHITE, font=FONT_TINY, anchor="lm")
        draw.text((320, y+15), arts, fill=C_GRAY, font=FONT_TINY, anchor="lm")
        draw.text((400, y+15), mitre, fill=C_GRAY, font=FONT_TINY, anchor="lm")
        draw.text((620, y+15), tact, fill=C_GRAY, font=FONT_TINY, anchor="lm")
        draw.text((800, y+15), ucs, fill=C_BLUE, font=FONT_TINY, anchor="lm")
        draw.text((1000, y+15), pct, fill=color, font=FONT_TINY, anchor="lm")
        draw_rounded_rect(draw, (1150, y+3, 1300, y+27), 3, fill=color)
        draw.text((1225, y+15), status, fill=C_WHITE, font=FONT_TINY, anchor="mm")

    # Charts mock
    draw_rounded_rect(draw, (20, 465, 680, 700), 8, fill=C_DARK, outline=C_BORDER)
    draw.text((40, 480), "MITRE ATT&CK Taktik-Heatmap", fill=C_WHITE, font=FONT_MED)

    bars = [("disc", 67, C_BLUE), ("cred", 45, C_RED), ("priv", 20, C_RED), ("evas", 35, C_ORANGE),
            ("lat", 30, C_RED), ("exec", 25, C_YELLOW), ("pers", 15, C_ORANGE), ("coll", 40, C_YELLOW),
            ("exfil", 35, C_RED), ("imp", 20, C_ACCENT)]
    for i, (label, val, color) in enumerate(bars):
        x = 50 + i * 62
        h = val * 2.5
        draw.rectangle((x, 680-h, x+50, 680), fill=color)
        draw.text((x+25, 690), label, fill=C_GRAY, font=FONT_TINY, anchor="mt")

    # SIEM Status
    draw_rounded_rect(draw, (700, 465, 1380, 700), 8, fill=C_DARK, outline=C_BORDER)
    draw.text((720, 480), "SIEM UseCase Trigger-Status", fill=C_WHITE, font=FONT_MED)

    uc_status = [
        ("UC-001 Cred Dump", "AKTIV", C_GREEN), ("UC-002 Priv Esc", "AKTIV", C_GREEN),
        ("UC-003 Recon", "AKTIV", C_GREEN), ("UC-004 Lat Mov", "AKTIV", C_GREEN),
        ("UC-005 Exec", "AKTIV", C_GREEN), ("UC-006 Exfil", "AKTIV", C_GREEN),
        ("UC-007 Evasion", "AKTIV", C_GREEN), ("UC-008 Persist", "AKTIV", C_GREEN),
        ("UC-009 Log Tamp", "AKTIV", C_GREEN), ("UC-010 Data Acc", "AKTIV", C_GREEN),
        ("UC-011 C2", "AKTIV", C_GREEN), ("UC-012 Ransom", "AKTIV", C_GREEN),
        ("UC-013 Mining", "INAKTIV", C_RED), ("UC-014 Impact", "AKTIV", C_GREEN),
        ("UC-015 Kill Ch", "AKTIV", C_ACCENT),
    ]
    for i, (name, status, color) in enumerate(uc_status):
        x = 720 + (i % 3) * 220
        y = 510 + (i // 3) * 35
        draw_rounded_rect(draw, (x, y, x+210, y+28), 4, fill=C_DARK, outline=color)
        draw.text((x+10, y+14), name, fill=C_WHITE, font=FONT_TINY, anchor="lm")
        draw_rounded_rect(draw, (x+155, y+4, x+205, y+24), 3, fill=color)
        draw.text((x+180, y+14), status, fill=C_WHITE, font=FONT_TINY, anchor="mm")

    # Timeline mock
    draw_rounded_rect(draw, (20, 715, 1380, 885), 8, fill=C_DARK, outline=C_BORDER)
    draw.text((40, 730), "Kill Chain Timeline - Angriffsphasen ueber Zeit", fill=C_WHITE, font=FONT_MED)

    # Simple timeline bars
    import random
    random.seed(42)
    phases = ["Recon", "Cred", "PrivEsc", "Evasion", "LatMov", "Collect", "Exfil", "Impact"]
    colors = [C_BLUE, C_RED, C_RED, C_ORANGE, C_RED, C_YELLOW, C_RED, C_ACCENT]
    for i, (phase, color) in enumerate(zip(phases, colors)):
        y = 760 + i * 14
        draw.text((40, y), phase, fill=C_GRAY, font=FONT_TINY, anchor="lm")
        for j in range(20):
            if random.random() < 0.3 + (i * 0.05):
                x = 120 + j * 60
                w = random.randint(10, 40)
                draw.rectangle((x, y-2, x+w, y+10), fill=color)

    img.save(os.path.join(OUT_DIR, "05_dashboard_mockup.png"), quality=95)
    print("05_dashboard_mockup.png created")


def create_installation_steps():
    """06 - Installation Steps Visual Guide"""
    img = Image.new("RGB", (1200, 850), C_BG)
    draw = ImageDraw.Draw(img)

    draw.text((600, 25), "Installations- und Betriebsschritte", fill=C_WHITE, font=FONT_LARGE, anchor="mt")

    steps = [
        ("1", "Caldera installieren", "git clone + pip install + Docker Build",
         "cd /opt && git clone https://github.com/mitre/caldera.git\ncd caldera && pip3 install -r requirements.txt\ndocker-compose up -d --build", C_ACCENT),
        ("2", "Adversary-Profile deployen", "6 Banking-Profile nach data/adversaries/ kopieren",
         "cp adversaries/bank-*.yml /opt/caldera/data/adversaries/\n# Profile: Ransomware, APT, Insider, LatMov, Evasion, Exfil", C_ORANGE),
        ("3", "Splunk App installieren", "Indexes, Lookups, Saved Searches, Dashboard",
         "export SPLUNK_PASS='*****'\n/opt/caldera-splunk/install-splunk-app.sh\n# Erstellt: caldera + siem_summary Index, 15 UseCases", C_BLUE),
        ("4", "Agents deployen", "Sandcat auf Zielsystemen installieren",
         "# Windows: server/deploy/sandcat.go-windows\n# Linux:   server/deploy/sandcat.go-linux\n# Agent meldet sich bei Caldera :8888", C_GREEN),
        ("5", "Tests ausfuehren", "Orchestrator startet alle 6 Profile sequentiell",
         "/opt/caldera-splunk/run-bank-adversaries.sh\n# Wartet auf Abschluss jeder Operation\n# Max 40 Min pro Profil, Jitter 2/8", C_YELLOW),
        ("6", "Ergebnisse publizieren", "Enriched Events nach Splunk senden",
         "/opt/caldera-splunk/publish-to-splunk.sh\n# Base64-Decode + MITRE-Enrichment\n# → Splunk HEC → Index caldera", C_YELLOW),
        ("7", "Dashboard pruefen", "Splunk Dashboard zeigt Ergebnisse",
         "https://<SPLUNK>/app/caldera_bank_siem/bank_purple_team\n# KPIs, MITRE Heatmap, UseCase Trigger\n# Erkennungsluecken-Analyse", C_GREEN),
        ("8", "Report erstellen", "DORA/TIBER-EU Compliance-Report",
         "# Dashboard → DORA Compliance Tab\n# Export: PDF via Splunk Report Builder\n# Dokumentation in docs/", C_ACCENT),
    ]

    for i, (num, title, desc, cmd, color) in enumerate(steps):
        x = 30 + (i % 2) * 590
        y = 70 + (i // 2) * 195

        draw_rounded_rect(draw, (x, y, x+570, y+185), 8, fill=C_DARK, outline=color, width=2)

        # Step number circle
        draw.ellipse((x+10, y+10, x+45, y+45), fill=color)
        draw.text((x+28, y+28), num, fill=C_WHITE, font=FONT_MED, anchor="mm")

        draw.text((x+55, y+15), title, fill=color, font=FONT_MED)
        draw.text((x+55, y+38), desc, fill=C_GRAY, font=FONT_SMALL)

        # Command box
        draw_rounded_rect(draw, (x+15, y+60, x+555, y+175), 5, fill="#0a0a0a", outline=C_BORDER)
        draw.text((x+25, y+65), "$ ", fill=C_GREEN, font=FONT_SMALL)
        for j, line in enumerate(cmd.split("\n")):
            color_line = C_GRAY if line.startswith("#") else C_WHITE
            draw.text((x+25, y+68+j*22), line, fill=color_line, font=FONT_TINY)

    img.save(os.path.join(OUT_DIR, "06_installation_steps.png"), quality=95)
    print("06_installation_steps.png created")


def create_mitre_coverage():
    """07 - MITRE Coverage Heatmap"""
    img = Image.new("RGB", (1200, 600), C_BG)
    draw = ImageDraw.Draw(img)

    draw.text((600, 25), "MITRE ATT&CK Abdeckung - Banking Use Cases", fill=C_WHITE, font=FONT_LARGE, anchor="mt")

    tactics = [
        ("Reconnaissance", 0, []),
        ("Initial Access", 0, []),
        ("Execution", 4, ["T1047","T1059","T1059.001","T1569.002"]),
        ("Persistence", 4, ["T1053","T1053.003","T1136","T1543.003"]),
        ("Priv. Escalation", 5, ["T1548","T1548.002","T1134","T1574","T1574.010"]),
        ("Def. Evasion", 11, ["T1027","T1036","T1055","T1055.001","T1055.002","T1070","T1070.001","T1070.003","T1070.004","T1497","T1562.001"]),
        ("Cred. Access", 8, ["T1003","T1003.001","T1003.003","T1040","T1552","T1552.002","T1552.003","T1552.004"]),
        ("Discovery", 10, ["T1016","T1018","T1049","T1057","T1082","T1083","T1087","T1087.001","T1087.002","T1482"]),
        ("Lat. Movement", 5, ["T1021","T1021.002","T1021.004","T1021.006","T1570"]),
        ("Collection", 8, ["T1005","T1074","T1074.001","T1113","T1115","T1119","T1560","T1560.001"]),
        ("Exfiltration", 8, ["T1029","T1030","T1041","T1048","T1048.003","T1537","T1567","T1567.001"]),
        ("C2", 3, ["T1071","T1071.001","T1105"]),
        ("Impact", 6, ["T1486","T1489","T1491","T1496","T1499","T1565"]),
    ]

    for i, (tactic, count, techs) in enumerate(tactics):
        x = 30
        y = 65 + i * 40

        # Tactic label
        draw.text((x, y+12), tactic, fill=C_WHITE, font=FONT_SMALL, anchor="lm")

        # Bar
        if count > 0:
            bar_w = count * 35
            intensity = min(255, 80 + count * 15)
            bar_color = f"#{intensity:02x}{max(0,80-count*5):02x}{max(0,60-count*3):02x}"
            if count >= 8:
                bar_color = C_RED
            elif count >= 5:
                bar_color = C_ORANGE
            elif count >= 3:
                bar_color = C_YELLOW
            else:
                bar_color = C_BLUE

            draw_rounded_rect(draw, (170, y, 170+bar_w, y+28), 4, fill=bar_color)
            draw.text((175+bar_w, y+14), f" {count} Techniken", fill=C_WHITE, font=FONT_SMALL, anchor="lm")

            # Technique labels
            tech_str = ", ".join(techs[:5])
            if len(techs) > 5:
                tech_str += f" +{len(techs)-5}"
            draw.text((600, y+14), tech_str, fill=C_GRAY, font=FONT_TINY, anchor="lm")
        else:
            draw.text((170, y+14), "Nicht abgedeckt (Out of Scope fuer Caldera)", fill="#444444", font=FONT_TINY, anchor="lm")

    # Total
    draw_rounded_rect(draw, (30, 590 - 40, 1170, 590), 5, fill=C_BORDER)
    draw.text((600, 570), "Gesamt: 63 Sub-/Techniken in 11 von 13 Taktiken abgedeckt | 79 Lookup-Eintraege | 15 SIEM UseCases",
              fill=C_WHITE, font=FONT_SMALL, anchor="mm")

    img.save(os.path.join(OUT_DIR, "07_mitre_coverage.png"), quality=95)
    print("07_mitre_coverage.png created")


if __name__ == "__main__":
    print("Generating documentation diagrams...")
    create_architecture_diagram()
    create_adversary_profiles_diagram()
    create_siem_usecases_diagram()
    create_data_flow_diagram()
    create_dashboard_mockup()
    create_installation_steps()
    create_mitre_coverage()
    print(f"\nAll diagrams saved to: {OUT_DIR}")
