"""
PhishGuard web app — Flask API + 3D front-end.

    python app.py            # http://127.0.0.1:5000
    PORT=8080 python app.py
"""

import os

from flask import Flask, jsonify, request, send_from_directory

from detector import detector, MAX_FIELD_LEN

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # reject huge uploads

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
    return jsonify(detector.analyze(**fields))


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Request too large."), 413


if __name__ == "__main__":
    detector.load()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  PhishGuard running →  http://127.0.0.1:{port}\n")
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=False)
