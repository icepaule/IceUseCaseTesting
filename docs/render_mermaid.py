#!/usr/bin/env python3
"""
Renders Mermaid .mmd files to PNG images using mermaid.ink API.
Fallback: uses mmdc (mermaid-cli) if available.
"""
import base64, glob, os, subprocess, sys, urllib.request, urllib.parse

MERMAID_DIR = os.path.join(os.path.dirname(__file__), "mermaid")
IMAGE_DIR = os.path.join(os.path.dirname(__file__), "images")

os.makedirs(IMAGE_DIR, exist_ok=True)


def render_via_api(mmd_content: str, output_path: str) -> bool:
    """Render via mermaid.ink public API."""
    encoded = base64.urlsafe_b64encode(mmd_content.encode()).decode()
    url = f"https://mermaid.ink/img/{encoded}?type=png&bgColor=!white&theme=default&width=1200"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CalderaPurpleTeam/1.0"})
        resp = urllib.request.urlopen(req, timeout=30)
        with open(output_path, "wb") as f:
            f.write(resp.read())
        return os.path.getsize(output_path) > 100
    except Exception as e:
        print(f"  [!] API render failed: {e}")
        return False


def render_via_mmdc(mmd_path: str, output_path: str) -> bool:
    """Render via mmdc (mermaid-cli)."""
    try:
        result = subprocess.run(
            ["mmdc", "-i", mmd_path, "-o", output_path, "-w", "1200", "-b", "white"],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except Exception:
        return False


def render_via_puppeteer(mmd_content: str, output_path: str) -> bool:
    """Render via inline puppeteer script."""
    try:
        html = f"""<!DOCTYPE html>
<html><head>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head><body>
<pre class="mermaid">{mmd_content}</pre>
<script>mermaid.initialize({{startOnLoad:true,theme:'default'}});</script>
</body></html>"""
        html_path = output_path.replace(".png", ".html")
        with open(html_path, "w") as f:
            f.write(html)
        return False  # Would need puppeteer
    except Exception:
        return False


def main():
    mmd_files = sorted(glob.glob(os.path.join(MERMAID_DIR, "*.mmd")))
    if not mmd_files:
        print("[!] No .mmd files found")
        sys.exit(1)

    print(f"[*] Found {len(mmd_files)} Mermaid diagrams")
    success = 0

    for mmd_path in mmd_files:
        name = os.path.splitext(os.path.basename(mmd_path))[0]
        output_path = os.path.join(IMAGE_DIR, f"{name}.png")
        print(f"  Rendering: {name}")

        with open(mmd_path) as f:
            content = f.read()

        # Try mmdc first, then API
        if render_via_mmdc(mmd_path, output_path):
            print(f"    [OK] via mmdc -> {output_path}")
            success += 1
        elif render_via_api(content, output_path):
            print(f"    [OK] via mermaid.ink -> {output_path}")
            success += 1
        else:
            print(f"    [FAIL] Could not render {name}")

    print(f"\n[*] Rendered {success}/{len(mmd_files)} diagrams")


if __name__ == "__main__":
    main()
