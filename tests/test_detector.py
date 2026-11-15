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
