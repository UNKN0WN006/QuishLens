from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pymupdf
import qrcode
from PIL import Image, ImageDraw, ImageFont

OUT = ROOT / "data" / "demo"
OUT.mkdir(parents=True, exist_ok=True)

SAMPLES = {
    "benign": "https://www.wikipedia.org/",
    "suspicious": "https://micros0ft-account-verify.example.invalid/login?continue=secure",
}

for name, url in SAMPLES.items():
    qr = qrcode.QRCode(version=None, box_size=9, border=4)
    qr.add_data(url); qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    canvas = Image.new("RGB", (900, 720), "white")
    canvas.paste(image.resize((420, 420)), (240, 190))
    draw = ImageDraw.Draw(canvas)
    title = "Security notice" if name == "suspicious" else "Wikipedia link"
    subtitle = "Scan to verify your account immediately" if name == "suspicious" else "Scan to open the public encyclopedia"
    draw.text((50, 45), title, fill="black")
    draw.text((50, 90), subtitle, fill="black")
    canvas.save(OUT / f"{name}_qr.png")

# PDF sample with contextual text + QR image.
doc = pymupdf.open()
page = doc.new_page(width=612, height=792)
page.insert_text((54, 75), "Microsoft 365 Security Notice", fontsize=19)
page.insert_textbox((54, 105, 558, 180), "Your account expires today. Scan the QR code and verify your password immediately to avoid suspension.", fontsize=12)
page.insert_image(pymupdf.Rect(116, 230, 496, 610), filename=str(OUT / "suspicious_qr.png"))
doc.save(OUT / "suspicious_notice.pdf")
doc.close()
print(f"Generated demo files in {OUT}")
