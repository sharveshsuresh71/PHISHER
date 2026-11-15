"""
PhishGuard web app — Flask API + 3D front-end.

    python app.py            # http://127.0.0.1:5000
    PORT=8080 python app.py
"""

import json
import os
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

import ocr
import webcheck
from detector import detector, MAX_FIELD_LEN
from narrator import narrate

def _load_dotenv():
    """Tiny .env reader so the Fish Audio key can live in a file next to app.py."""
    f = Path(__file__).resolve().parent / ".env"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


_load_dotenv()
FISH_URL = "https://api.fish.audio/v1/tts"
FISH_VOICE = os.environ.get("FISH_VOICE_ID", "c35aeeb5f9c145199fbffdbc2ef8ed95")
FISH_MODEL = os.environ.get("FISH_MODEL", "s2.1-pro")
_hits = defaultdict(deque)  # per-IP rate limit so nobody can drain your Fish credits

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # screenshots; JSON fields are capped separately

SAMPLES = [
    {"id": "paypal", "label": "PayPal scam", "subject": "Urgent: Your PayPal account has been suspended",
     "sender": "support@paypal-security.tk",
     "body": "Dear valued customer,\n\nWe detected unusual activity on your PayPal account. Verify your identity "
             "immediately by clicking the link below:\n\nhttp://paypal-verify-account.com/login\n\n"
             "Failure to respond within 24 hours will result in permanent suspension!!!"},
    {"id": "ceo", "label": "CEO wire fraud", "subject": "Quick favor",
     "sender": "michael.brown@gmail.com",
     "body": "Hi, are you available? I need you to handle a confidential wire transfer of $18,400 to a new vendor "
             "today. I'm in a meeting so can't call. Don't discuss this with anyone.\n\nMichael"},
    {"id": "parcel", "label": "Parcel fee", "subject": "Your DHL package could not be delivered",
     "sender": "delivery@dhl-parcel.xyz",
     "body": "Your parcel is on hold due to an incomplete address. Pay a small redelivery fee here:\n\n"
             "http://bit.ly/3xJ9kLp\n\nWe'll return it to sender within 24 hrs."},
    {"id": "amazon", "label": "Real Amazon", "subject": "Your Amazon order has shipped",
     "sender": "ship-confirm@amazon.com",
     "body": "Hi, your order #114-2233 has shipped and should arrive Thursday.\n\n"
             "Track it here: https://www.amazon.com/progress-tracker\n\nAmazon Customer Care"},
    {"id": "meeting", "label": "Work email", "subject": "Team meeting moved to 3 PM",
     "sender": "alex@company.com",
     "body": "Hi team,\n\nOur meeting has moved to 3 PM today in conference room B. Please bring your quarterly "
             "reports.\n\nThanks,\nAlex"},
    {"id": "google", "label": "Real Google alert", "subject": "Security alert",
     "sender": "no-reply@accounts.google.com",
     "body": "A new sign-in to your Google account was detected on a Windows device. If this was you, you don't "
             "need to do anything.\n\nhttps://accounts.google.com/security"},
]


SITE_SAMPLES = [
    {"label": "Fake PayPal login", "url": "http://paypa1-account-verify.com/signin?verify=1"},
    {"label": "Brand in subdomain", "url": "https://paypal.com.secure-login.verify-id.xyz/update"},
    {"label": "Raw IP login", "url": "http://185.234.12.9:8080/bank/login"},
    {"label": "Real Google", "url": "https://accounts.google.com/signin"},
    {"label": "Real GitHub", "url": "https://github.com/anthropics"},
]


@app.get("/api/site-samples")
def site_samples():
    return jsonify(SITE_SAMPLES)


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/health")
def health():
    detector.load()
    return jsonify(status="ok", model=detector.metrics.get("model"))


@app.get("/api/stats")
def stats():
    detector.load()
    return jsonify(detector.metrics)


@app.get("/api/samples")
def samples():
    return jsonify(SAMPLES)


@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Send a JSON body with subject, sender and body."), 400
    fields = {k: data.get(k, "") for k in ("subject", "sender", "body")}
    if any(v is not None and not isinstance(v, str) for v in fields.values()):
        return jsonify(error="subject, sender and body must be strings."), 400
    if not any((v or "").strip() for v in fields.values()):
        return jsonify(error="Paste an email to analyze."), 400
    if any(len(v or "") > MAX_FIELD_LEN for v in fields.values()):
        return jsonify(error=f"Each field is limited to {MAX_FIELD_LEN} characters."), 413
    result = detector.analyze(**fields)
    result["kind"] = "email"
    result["narration"] = narrate(result)
    return jsonify(result)


@app.post("/api/analyze-url")
def analyze_url():
    data = request.get_json(silent=True)
    url = data.get("url") if isinstance(data, dict) else None
    if not isinstance(url, str) or not url.strip():
        return jsonify(error="Enter a website address to check."), 400
    if len(url) > webcheck.MAX_URL_LEN:
        return jsonify(error="That address is too long."), 413
    try:
        result = webcheck.analyze_url(url)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    result["narration"] = narrate(result)
    return jsonify(result)


@app.get("/api/speak/status")
def speak_status():
    return jsonify(fish=bool(os.environ.get("FISH_API_KEY")))


@app.post("/api/speak")
def speak():
    """Text → speech in your Fish Audio reference voice. The API key never leaves the server."""
    key = os.environ.get("FISH_API_KEY")
    if not key:
        return jsonify(error="Fish Audio is not configured.", fallback="browser"), 501
    data = request.get_json(silent=True)
    text = data.get("text") if isinstance(data, dict) else None
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="No text to speak."), 400
    if len(text) > 1500:
        return jsonify(error="Text too long (1500 characters max)."), 413
    now, q = time.time(), _hits[request.remote_addr]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 30:
        return jsonify(error="Too many voice requests — wait a minute."), 429
    q.append(now)
    try:
        speed = min(max(float(data.get("speed", 1)), 0.7), 1.4)
    except (TypeError, ValueError):
        speed = 1.0
    body = json.dumps({"text": text.strip(), "reference_id": FISH_VOICE, "format": "mp3",
                       "latency": "balanced", "prosody": {"speed": speed}}).encode()
    req = urllib.request.Request(FISH_URL, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json", "model": FISH_MODEL})
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            audio = r.read()
    except urllib.error.HTTPError as exc:
        msg = {401: "Fish Audio rejected the API key.", 402: "Fish Audio account is out of credit."}.get(
            exc.code, f"Fish Audio error ({exc.code}).")
        return jsonify(error=msg, fallback="browser"), 502
    except Exception:
        return jsonify(error="Could not reach Fish Audio.", fallback="browser"), 502
    return Response(audio, mimetype="audio/mpeg", headers={"Cache-Control": "no-store"})


@app.get("/api/ocr/status")
def ocr_status():
    return jsonify(server_ocr=ocr.available())


@app.post("/api/ocr")
def ocr_image():
    """Screenshot → text. Returns an email split and any URL found."""
    f = request.files.get("image")
    if f is None:
        return jsonify(error="Attach an image in the 'image' field."), 400
    if not ocr.available():
        return jsonify(error="Server OCR is not installed.", fallback="browser"), 501
    try:
        text = ocr.image_to_text(f.read())
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception:
        return jsonify(error="Could not read text from that image."), 500
    if not text.strip():
        return jsonify(error="No readable text found in that image."), 422
    return jsonify(text=text, url=webcheck.find_url(text), **ocr.split_email(text))


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Request too large."), 413


if __name__ == "__main__":
    detector.load()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  PhishGuard running →  http://127.0.0.1:{port}\n")
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=False)
