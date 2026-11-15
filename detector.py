"""
Inference + explanation layer used by the web app (app.py).

Loads the trained artifacts (training automatically on first run if they are
missing) and turns a raw email into a verdict plus human-readable evidence.
"""

import json
import threading

import joblib
import numpy as np
import pandas as pd

import train
from features import analyze_email, build_feature_matrix, FEATURE_NAMES, BRAND_DOMAINS

MAX_FIELD_LEN = 20000


class Detector:
    def __init__(self):
        self._lock = threading.Lock()
        self.model = self.tfidf = self.scaler = self.explainer = None
        self.metrics = {}

    # ------------------------------------------------------------------
    def load(self):
        with self._lock:
            if self.model is not None:
                return self
            if not all(p.exists() for p in (train.MODEL_PATH, train.TFIDF_PATH, train.SCALER_PATH, train.EXPLAINER_PATH)):
                print("[detector] No trained model found — training one now...")
                train.main(verbose=False)
            try:
                self.model = joblib.load(train.MODEL_PATH)
                self.tfidf = joblib.load(train.TFIDF_PATH)
                self.scaler = joblib.load(train.SCALER_PATH)
            except Exception as exc:  # e.g. scikit-learn version mismatch
                print(f"[detector] Could not load saved model ({exc!r}) — retraining...")
                train.main(verbose=False)
                self.model = joblib.load(train.MODEL_PATH)
                self.tfidf = joblib.load(train.TFIDF_PATH)
                self.scaler = joblib.load(train.SCALER_PATH)
            self.explainer = joblib.load(train.EXPLAINER_PATH) if train.EXPLAINER_PATH.exists() else None
            if train.METRICS_PATH.exists():
                self.metrics = json.loads(train.METRICS_PATH.read_text())
            return self

    # ------------------------------------------------------------------
    def analyze(self, subject="", body="", sender=""):
        self.load()
        subject, body, sender = (str(x or "")[:MAX_FIELD_LEN] for x in (subject, body, sender))

        df = pd.DataFrame([{"subject": subject, "body": body, "sender": sender}])
        X, _, _ = build_feature_matrix(df, self.tfidf, self.scaler, fit=False)
        classes = list(self.model.classes_)
        p_phish = float(self.model.predict_proba(X)[0][classes.index("phishing")])

        feats, details = analyze_email(subject, body, sender)
        if p_phish >= 0.70:
            verdict = "PHISHING"
        elif p_phish >= 0.35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return {
            "verdict": verdict,
            "score": round(p_phish, 4),
            "probabilities": {"phishing": round(p_phish, 4), "safe": round(1 - p_phish, 4)},
            "signals": self._signals(feats, details),
            "urls": details["urls"],
            "terms": self._terms(X),
            "model": self.metrics.get("model", type(self.model).__name__),
        }

    # ------------------------------------------------------------------
    def _terms(self, X, top=6):
        """Words/phrases in this email that push the model most toward phishing."""
        names = list(self.tfidf.get_feature_names_out())
        n_text = len(names)
        row = X[0]
        idx = row.indices[row.indices < n_text]
        vals = row.data[row.indices < n_text]
        lin = self.explainer if self.explainer is not None else self.model
        if not hasattr(lin, "coef_"):
            return []
        sign = 1.0 if list(lin.classes_)[1] == "phishing" else -1.0
        w = sign * lin.coef_[0][idx]
        contrib = w * vals
        order = np.argsort(contrib)[::-1][:top]
        return [{"term": names[idx[i]], "weight": round(float(contrib[i]), 4)}
                for i in order if contrib[i] > 0]

    @staticmethod
    def _signals(f, d):
        """Human-readable risk (bad) and trust (good) signals, each with 0..1 strength."""
        out = []

        def add(kind, title, detail, strength):
            out.append({"kind": kind, "title": title, "detail": detail,
                        "strength": round(float(min(max(strength, 0.05), 1.0)), 2)})

        s_dom = d["sender_domain"] or "unknown"
        if f["sender_lookalike"]:
            add("risk", "Look-alike sender domain", f"{s_dom} imitates {', '.join(d['lookalike_sender'])} but isn't official", 1.0)
        if f["brand_sender_mismatch"]:
            add("risk", "Brand / sender mismatch",
                f"Mentions {', '.join(d['mismatch_brands'])} but sender is {s_dom}", 0.75)
        if f["sender_suspicious_tld"]:
            add("risk", "High-risk sender domain", f"{s_dom} uses a TLD common in abuse", 0.7)
        if f["freemail_sender"] and (f["money_keyword_count"] or f["brand_sender_mismatch"]):
            add("risk", "Free-mail sender", f"{s_dom} is a free mailbox but the email asks for money or acts as a brand", 0.55)
        if f["url_brand_mismatch"]:
            add("risk", "Link imitates a brand", f"Links look like {', '.join(d['lookalike_urls'])} but go elsewhere", 1.0)
        if f["has_ip_url"]:
            add("risk", "Link to a raw IP address", "Legitimate companies almost never link to bare IPs", 0.95)
        if f["has_shortener"]:
            add("risk", "URL shortener", "The real destination of the link is hidden", 0.7)
        if f["has_suspicious_tld"]:
            add("risk", "High-risk link domain", "A link uses a TLD common in abuse (.ru, .tk, .xyz …)", 0.8)
        if f["has_at_in_url"]:
            add("risk", "'@' trick in link", "Text before '@' in a URL can disguise the real host", 0.9)
        if f["max_host_hyphens"] >= 2:
            add("risk", "Hyphen-stuffed domain", f"Link host has {f['max_host_hyphens']} hyphens", 0.5)
        if f["non_https_url_count"]:
            add("risk", "Insecure link", f"{f['non_https_url_count']} link(s) use http:// not https://", 0.4)
        if f["url_sender_mismatch"] and not f["url_brand_mismatch"]:
            add("risk", "Link domain differs from sender", "Links point to a different site than the sender's", 0.35)
        if f["urgency_keyword_count"]:
            add("risk", "Urgency / pressure language",
                f"{f['urgency_keyword_count']} phrases: " + ", ".join(d["urgency_hits"][:4]), f["urgency_keyword_count"] / 5)
        if f["credential_keyword_count"]:
            add("risk", "Asks for credentials / sensitive data",
                ", ".join(d["credential_hits"][:4]), f["credential_keyword_count"] / 4)
        if f["money_keyword_count"] >= 2 and f["freemail_sender"]:
            add("risk", "Money-transfer wording", "Payment / wire language from a personal mailbox", 0.6)
        if f["exclamation_count"] >= 2:
            add("risk", "Excessive exclamation marks", f"{f['exclamation_count']} found", f["exclamation_count"] / 6)
        if f["all_caps_word_count"] >= 2:
            add("risk", "ALL-CAPS shouting", f"{f['all_caps_word_count']} capitalised words", f["all_caps_word_count"] / 6)

        # trust signals
        if d["brands"] and not f["brand_sender_mismatch"] and not f["sender_lookalike"]:
            add("good", "Sender matches the brand", f"{s_dom} is an official domain for {', '.join(d['brands'])}", 0.8)
        if d["urls"] and not any(u["insecure"] or u["ip"] or u["shortener"] or u["bad_tld"] or u["lookalike"] for u in d["urls"]):
            add("good", "Clean links", "All links use https and normal domains", 0.6)
        if not d["urls"]:
            add("good", "No links", "No clickable links in this email", 0.3)
        if not any(s["kind"] == "risk" for s in out):
            add("good", "No phishing indicators", "No handcrafted red flags were triggered", 0.7)

        out.sort(key=lambda s: (s["kind"] != "risk", -s["strength"]))
        return out


detector = Detector()
