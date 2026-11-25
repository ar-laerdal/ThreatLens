"""Generate the sample e-commerce architecture diagram (PNG) with Pillow.

Usage:  python data/sample_architecture/generate_diagram.py
The diagram mirrors ecommerce_design.md.
"""
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).with_name("ecommerce_architecture.png")
W, H = 1600, 900

ZONES = [  # label, x0, y0, x1, y1, colour
    ("INTERNET", 20, 60, 330, 860, "#FDECEC"),
    ("DMZ", 350, 60, 640, 860, "#FFF4E0"),
    ("INTERNAL NETWORK", 660, 60, 1170, 860, "#E8F7F1"),
    ("THIRD-PARTY", 1190, 60, 1580, 860, "#F0EBFA"),
]
NODES = {  # key: (label, subtitle, cx, cy)
    "fe": ("Web Frontend", "React SPA (browser)", 175, 240),
    "gw": ("API Gateway", "TLS, rate limit, JWT check", 495, 450),
    "auth": ("Authentication Service", "login, JWT issuance", 915, 170),
    "app": ("Application Backend", "REST API (Python)", 915, 450),
    "db": ("User Database", "PostgreSQL", 915, 730),
    "obj": ("Object Storage", "S3 bucket (images, invoices)", 1080, 590),
    "pay": ("Payment Gateway", "card payments", 1385, 250),
    "note": ("Notification Service", "email / SMS provider", 1385, 650),
}
BOX_W, BOX_H = 230, 80
EDGES = [  # src, dst, label
    ("fe", "gw", "1 HTTPS: API requests"),
    ("gw", "auth", "2 HTTP: credentials/tokens"),
    ("gw", "app", "3 HTTP: API requests"),
    ("auth", "db", "4 TLS: accounts"),
    ("app", "db", "5 TLS: orders, profiles"),
    ("app", "obj", "6 HTTPS: images, invoices"),
    ("fe", "pay", "7 HTTPS: card details"),
    ("app", "pay", "8 HTTPS: token, amount"),
    ("pay", "gw", "9 webhook: result"),
    ("app", "note", "10 HTTPS: PII, order"),
]


def _font(size: int):
    try:
        return ImageFont.load_default(size=size)
    except TypeError:  # Pillow < 10.1
        return ImageFont.load_default()


def _edge_point(cx, cy, tx, ty):
    """Point on the box border facing (tx, ty)."""
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0:
        return cx, cy
    scale = min((BOX_W / 2) / abs(dx) if dx else math.inf, (BOX_H / 2) / abs(dy) if dy else math.inf)
    return cx + dx * scale, cy + dy * scale


def _arrow(draw, p0, p1, label, font):
    draw.line([p0, p1], fill="#34455E", width=3)
    angle = math.atan2(p1[1] - p0[1], p1[0] - p0[0])
    tip = p1
    left = (tip[0] - 14 * math.cos(angle - 0.4), tip[1] - 14 * math.sin(angle - 0.4))
    right = (tip[0] - 14 * math.cos(angle + 0.4), tip[1] - 14 * math.sin(angle + 0.4))
    draw.polygon([tip, left, right], fill="#34455E")
    mid = ((p0[0] + p1[0]) / 2, (p0[1] + p1[1]) / 2)
    box = draw.textbbox(mid, label, font=font, anchor="mm")
    draw.rectangle((box[0] - 3, box[1] - 2, box[2] + 3, box[3] + 2), fill="white")
    draw.text(mid, label, fill="#1F2A3C", font=font, anchor="mm")


def generate(path: Path = OUT) -> Path:
    img = Image.new("RGB", (W, H), "white")
    draw = ImageDraw.Draw(img)
    big, mid, small = _font(26), _font(18), _font(14)

    draw.text((W / 2, 30), "ShopFast E-Commerce Platform - Architecture", fill="#0B1220", font=big, anchor="mm")
    for label, x0, y0, x1, y1, colour in ZONES:
        draw.rounded_rectangle((x0, y0, x1, y1), radius=14, fill=colour, outline="#8B98A9", width=2)
        draw.text((x0 + 12, y0 + 10), label, fill="#4B5565", font=mid)

    for src, dst, label in EDGES:
        (_, _, sx, sy), (_, _, dx, dy) = NODES[src], NODES[dst]
        _arrow(draw, _edge_point(sx, sy, dx, dy), _edge_point(dx, dy, sx, sy), label, small)

    for title, sub, cx, cy in NODES.values():
        box = (cx - BOX_W / 2, cy - BOX_H / 2, cx + BOX_W / 2, cy + BOX_H / 2)
        draw.rounded_rectangle(box, radius=10, fill="#0B1220", outline="#00A383", width=3)
        draw.text((cx, cy - 12), title, fill="white", font=mid, anchor="mm")
        draw.text((cx, cy + 16), sub, fill="#9FB3C8", font=small, anchor="mm")

    img.save(path, "PNG")
    return path


if __name__ == "__main__":
    print(generate())
