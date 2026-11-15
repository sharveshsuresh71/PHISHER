"""
Screenshot → text. Uses the ``tesseract`` command-line program when it is
installed (apt install tesseract-ocr / brew install tesseract / Windows installer).
If it is missing, ``available()`` is False and the web UI falls back to
in-browser OCR (tesseract.js), so uploads still work.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageOps, ImageStat

MAX_PIXELS = 40_000_000
_WIN = [r"C:\Program Files\Tesseract-OCR\tesseract.exe", r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"]


def _binary():
    exe = shutil.which("tesseract")
    if exe:
        return exe
    return next((p for p in _WIN if Path(p).exists()), None)


def available() -> bool:
    return _binary() is not None


def image_to_text(data: bytes) -> str:
    exe = _binary()
    if not exe:
        raise RuntimeError("OCR engine not installed")
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception as exc:
        raise ValueError("That file isn't a readable image.") from exc
    img = ImageOps.exif_transpose(img).convert("RGB")
    if img.width < 1200:  # small screenshots OCR much better when upscaled
        f = 1600 / img.width
        img = img.resize((1600, int(img.height * f)), Image.LANCZOS)
    img = ImageOps.autocontrast(ImageOps.grayscale(img))
    if ImageStat.Stat(img).mean[0] < 110:  # dark-mode screenshot → invert
        img = ImageOps.invert(img)

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "in.png"
        img.save(p)
        out = subprocess.run([exe, str(p), "stdout", "--psm", "6", "-l", "eng"],
                             capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError("OCR failed")
    return out.stdout


def split_email(text: str) -> dict:
    """Best-effort split of OCR'd text into sender / subject / body."""
    text = (text or "").replace("\r", "")
    sender = subject = ""
    lines = text.split("\n")
    body_start = 0
    for i, ln in enumerate(lines[:12]):
        m = re.match(r"\s*(from|sender)\s*[:：]\s*(.+)", ln, re.I)
        if m and not sender:
            em = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", m.group(2))
            sender = em.group(0) if em else m.group(2).strip()
            body_start = max(body_start, i + 1)
        m = re.match(r"\s*subject\s*[:：]\s*(.+)", ln, re.I)
        if m and not subject:
            subject = m.group(1).strip()
            body_start = max(body_start, i + 1)
    if not sender:
        em = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text)
        sender = em.group(0) if em else ""
    body = "\n".join(lines[body_start:]).strip() if body_start else text.strip()
    body = re.sub(r"\n{3,}", "\n\n", body)
    return {"sender": sender, "subject": subject, "body": body}
