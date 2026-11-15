import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features import _extract_urls, analyze_email  # noqa: E402
from detector import detector  # noqa: E402
from app import app  # noqa: E402

PHISH = [
    ("Dear user, your mailbox is full", "Your mailbox storage is 99% full. Login at http://mailbox-upgrade.top/login to keep receiving mail.", "admin@helpdesk-mail.top"),
    ("Invoice", "Please wire $4,500 to the new bank account today. Keep this confidential.", "ceo@gmail.com"),
    ("Netflix: payment declined", "Update it here: https://netflix-billing.support/update or your membership ends today!", "billing@netflix-billing.support"),
    ("Verify your Microsoft account", "Click https://login.microsoftonline.com.verify-id.net/ to keep access", "security@microsoft.com.verify-id.net"),
    ("Claim your reward!!!", "You WON a free iPhone. Click here http://bit.ly/abc123 now", "promo@rewards-center.xyz"),
]
SAFE = [
    ("Your Amazon order has shipped", "Track: https://www.amazon.com/progress-tracker", "ship-confirm@amazon.com"),
    ("Security alert", "New sign-in to your Google account. If this was you, no action needed. https://accounts.google.com/security", "no-reply@accounts.google.com"),
    ("Lunch", "First purchase of the day, let's chase the deadline.", "bob@firm.com"),
    ("Standup moved", "Standup is at 10 tomorrow. Update tickets on https://jira.company.com/board", "pm@company.com"),
    ("Your GitHub login code", "Your verification code is 482913. It expires in 10 minutes.", "noreply@github.com"),
]


@pytest.mark.parametrize("s,b,f", PHISH)
def test_phishing_detected(s, b, f):
    assert detector.analyze(s, b, f)["verdict"] in ("PHISHING", "SUSPICIOUS")


@pytest.mark.parametrize("s,b,f", SAFE)
def test_safe_detected(s, b, f):
    assert detector.analyze(s, b, f)["verdict"] == "SAFE"


def test_url_trailing_punctuation_stripped():
    assert _extract_urls("see http://evil.tk, and http://a.ru.") == ["http://evil.tk", "http://a.ru"]


def test_brand_word_boundaries():
    # 'chase' inside 'purchase' / 'irs' inside 'first' must not count as brands
    _, d = analyze_email("First purchase", "I will purchase it first", "a@b.com")
    assert d["brands"] == []


def test_none_inputs_do_not_crash():
    assert detector.analyze(None, None, None)["verdict"] in ("SAFE", "SUSPICIOUS", "PHISHING")


def test_api():
    c = app.test_client()
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/stats").get_json()["n_emails"] > 0
    assert c.post("/api/analyze", json={}).status_code == 400
    assert c.post("/api/analyze", data="nope").status_code == 400
    assert c.post("/api/analyze", json={"body": "x" * 30000}).status_code == 413
    r = c.post("/api/analyze", json={"subject": "Verify now", "sender": "a@paypal-security.tk", "body": "http://192.168.1.1/login"})
    assert r.status_code == 200 and r.get_json()["verdict"] == "PHISHING"


# ---------- website analysis, narration, OCR ----------
import webcheck  # noqa: E402
import ocr  # noqa: E402

BAD_SITES = ["http://paypa1-account-verify.com/signin", "https://paypal.com.secure-login.verify-id.xyz/update",
             "http://185.234.12.9:8080/bank/login", "http://xn--pypal-4ve.com/login"]
GOOD_SITES = ["https://accounts.google.com/signin", "https://github.com/anthropics", "https://www.amazon.in/gp/css/order",
              "https://news.bbc.co.uk/sport", "https://example.com/"]


@pytest.mark.parametrize("u", BAD_SITES)
def test_bad_sites_flagged(u):
    assert webcheck.analyze_url(u)["verdict"] == "PHISHING"


@pytest.mark.parametrize("u", GOOD_SITES)
def test_good_sites_safe(u):
    assert webcheck.analyze_url(u)["verdict"] == "SAFE"


def test_url_api_and_narration():
    c = app.test_client()
    assert c.post("/api/analyze-url", json={}).status_code == 400
    assert c.post("/api/analyze-url", json={"url": "hello"}).status_code == 400
    r = c.post("/api/analyze-url", json={"url": "http://paypa1-account-verify.com/signin"}).get_json()
    assert r["verdict"] == "PHISHING" and r["narration"]["chunks"] and "Warning" in r["narration"]["text"]
    e = c.post("/api/analyze", json={"subject": "x", "sender": "a@paypal-security.tk", "body": "http://192.168.1.1/login"}).get_json()
    assert e["narration"]["text"] and e["kind"] == "email"


def test_find_url():
    assert webcheck.find_url("go to https://evil.tk/login, now") == "https://evil.tk/login"
    assert webcheck.find_url("see paypa1-secure.com/verify") == "paypa1-secure.com/verify"


def test_split_email():
    d = ocr.split_email("From: Support <support@paypa1.com>\nSubject: Verify now\n\nClick http://x.tk")
    assert d["sender"] == "support@paypa1.com" and d["subject"] == "Verify now" and d["body"].startswith("Click")


@pytest.mark.skipif(not ocr.available(), reason="tesseract not installed")
def test_ocr_endpoint():
    import io
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (900, 260), "white")
    d = ImageDraw.Draw(img)
    try:
        f = ImageFont.truetype("DejaVuSans.ttf", 28)
    except OSError:
        f = ImageFont.load_default()
    d.text((20, 20), "From: security@paypa1-account-verify.com", fill="black", font=f)
    d.text((20, 80), "Subject: Verify your account immediately", fill="black", font=f)
    d.text((20, 150), "Login now: http://paypa1-account-verify.com/signin", fill="black", font=f)
    buf = io.BytesIO(); img.save(buf, "PNG"); buf.seek(0)
    r = app.test_client().post("/api/ocr", data={"image": (buf, "s.png")}, content_type="multipart/form-data")
    j = r.get_json()
    assert r.status_code == 200, j
    # OCR may read a look-alike "1" as "l" — either way the fake domain must still be caught
    import re
    assert re.search(r"paypa[1l]-account-verify\.com", j["sender"]) and "immediately" in j["subject"].lower()
    assert re.search(r"paypa[1l]-account-verify\.com", j["url"])
    assert detector.analyze(j["subject"], j["body"], j["sender"])["verdict"] in ("PHISHING", "SUSPICIOUS")
    assert app.test_client().post("/api/ocr", data={"image": (io.BytesIO(b"nope"), "s.png")}, content_type="multipart/form-data").status_code == 400


# ---------- Fish Audio proxy (network mocked) ----------
import io as _io  # noqa: E402
import urllib.error  # noqa: E402


class _Resp(_io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_speak_not_configured(monkeypatch):
    monkeypatch.delenv("FISH_API_KEY", raising=False)
    c = app.test_client()
    assert c.get("/api/speak/status").get_json() == {"fish": False}
    assert c.post("/api/speak", json={"text": "hi"}).status_code == 501


def test_speak_proxy(monkeypatch):
    import app as appmod
    monkeypatch.setenv("FISH_API_KEY", "k")
    appmod._hits.clear()
    seen = {}

    def fake(req, timeout=0):
        seen["h"] = dict(req.header_items()); seen["b"] = __import__("json").loads(req.data)
        return _Resp(b"ID3audio")
    monkeypatch.setattr(appmod.urllib.request, "urlopen", fake)
    c = app.test_client()
    r = c.post("/api/speak", json={"text": "Warning.", "speed": 1.15})
    assert r.status_code == 200 and r.data == b"ID3audio" and r.mimetype == "audio/mpeg"
    assert seen["b"]["reference_id"] == "c35aeeb5f9c145199fbffdbc2ef8ed95" and seen["h"]["Authorization"] == "Bearer k"
    assert c.post("/api/speak", json={"text": "x" * 2000}).status_code == 413
    assert c.post("/api/speak", json={"text": " "}).status_code == 400

    def boom(req, timeout=0):
        raise urllib.error.HTTPError("u", 402, "pay", {}, None)
    monkeypatch.setattr(appmod.urllib.request, "urlopen", boom)
    r = c.post("/api/speak", json={"text": "hi"})
    assert r.status_code == 502 and "credit" in r.get_json()["error"] and r.get_json()["fallback"] == "browser"
