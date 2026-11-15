"""
Feature engineering for phishing email detection.

Produces a numeric feature matrix from raw email fields (subject, body,
sender) capturing well-known phishing signals:
    - URL-based features (count, IP-based links, shortened links, brand
      look-alike domains, suspicious TLDs, insecure http links)
    - Keyword / urgency features ("verify", "suspended", "click here", ...)
    - Structural features (exclamation marks, all-caps words, length,
      presence of dollar amounts)
    - Sender-based features (brand/sender mismatch, look-alike domains,
      free-mail senders, suspicious TLDs)

These handcrafted features are combined with TF-IDF text features in
``build_feature_matrix`` (used by train.py and detector.py).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\)\]\"']+", re.IGNORECASE)
IPV4_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
TRAILING_PUNCT = ".,;:!?)]}>'\""

SHORTENER_DOMAINS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
)
SUSPICIOUS_TLDS = (
    ".ru", ".tk", ".xyz", ".info", ".click", ".top", ".cn", ".zip", ".work",
    ".gq", ".ml", ".cf", ".ga", ".icu", ".buzz", ".support", ".country",
)
FREEMAIL_DOMAINS = (
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "proton.me", "protonmail.com", "mail.com", "gmx.com", "yandex.com",
)

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "verify your", "suspended",
    "suspension", "unusual activity", "final notice", "final warning",
    "click here", "confirm your identity", "limited time", "act now",
    "password will expire", "security alert", "restricted", "unauthorized",
    "locked", "expire", "update your payment", "winner", "congratulations",
    "claim your", "free gift", "refund", "failure to", "permanently",
    "within 24", "within 48", "deactivat", "validate your", "do not ignore",
]

CREDENTIAL_KEYWORDS = [
    "password", "credentials", "username", "login", "log in", "sign in",
    "credit card", "card number", "cvv", "ssn", "social security",
    "bank account", "routing number", "otp", "one-time code", "pin number",
]

MONEY_KEYWORDS = [
    "wire", "bank transfer", "gift card", "bitcoin", "crypto", "western union",
    "payment", "invoice", "new bank account", "transfer the funds", "$",
]

# brand -> official domains (a sender/link on these domains is "legit")
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "office.com", "microsoftonline.com", "live.com", "outlook.com"],
    "bank of america": ["bankofamerica.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonses.com"],
    "chase": ["chase.com"],
    "dhl": ["dhl.com"],
    "irs": ["irs.gov"],
    "linkedin": ["linkedin.com"],
    "wells fargo": ["wellsfargo.com"],
    "google": ["google.com", "gmail.com"],
    "facebook": ["facebook.com", "facebookmail.com", "fb.com"],
    "instagram": ["instagram.com"],
    "dropbox": ["dropbox.com"],
    "spotify": ["spotify.com"],
    "github": ["github.com"],
    "zoom": ["zoom.us"],
    "docusign": ["docusign.com", "docusign.net"],
}
BRAND_NAMES = list(BRAND_DOMAINS)
_BRAND_REGEX = {b: re.compile(r"\b" + re.escape(b) + r"\b") for b in BRAND_NAMES}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})

FEATURE_NAMES = [
    "url_count", "has_ip_url", "has_shortener", "has_suspicious_tld",
    "urgency_keyword_count", "exclamation_count", "dollar_sign_present",
    "all_caps_word_count", "body_length", "subject_length",
    "brand_sender_mismatch", "sender_suspicious_tld",
    "url_brand_mismatch", "sender_lookalike", "non_https_url_count",
    "max_host_hyphens", "credential_keyword_count", "money_keyword_count",
    "freemail_sender", "url_sender_mismatch", "has_at_in_url",
]


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _s(x) -> str:
    """Safe string: None / NaN -> ''."""
    if x is None:
        return ""
    if isinstance(x, float) and np.isnan(x):
        return ""
    return str(x)


def _extract_urls(text):
    """Return URLs with trailing sentence punctuation stripped."""
    urls = []
    for u in URL_REGEX.findall(_s(text)):
        u = u.rstrip(TRAILING_PUNCT)
        if u:
            urls.append(u)
    return urls


def _host(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def _sender_domain(sender: str) -> str:
    sender = _s(sender).strip().lower().rstrip(">")
    return sender.rsplit("@", 1)[-1].strip() if "@" in sender else ""


def _on_domain(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _has_ip_url(urls):
    return any(IPV4_REGEX.match(_host(u)) for u in urls)


def _has_shortener(urls):
    return any(_on_domain(_host(u), SHORTENER_DOMAINS) for u in urls)


def _has_suspicious_tld(urls):
    return any(_host(u).endswith(SUSPICIOUS_TLDS) for u in urls)


def _count_keywords(text, keywords):
    text_lower = _s(text).lower()
    return sum(text_lower.count(kw) for kw in keywords)


def _all_caps_word_count(text):
    return len(re.findall(r"\b[A-Z]{3,}\b", _s(text)))


def _brands_in_text(text):
    text_lower = _s(text).lower()
    return [b for b, rx in _BRAND_REGEX.items() if rx.search(text_lower)]


def _imitates_brand(domain: str, brand: str) -> bool:
    """True if ``domain`` contains the brand name (incl. 0/1/3 look-alikes)
    but is not one of the brand's official domains."""
    if not domain or _on_domain(domain, BRAND_DOMAINS[brand]):
        return False
    token = brand.replace(" ", "")
    flat = domain.translate(_LEET).replace("-", "").replace(".", "")
    return token in domain.replace("-", "") or token in flat


# --------------------------------------------------------------------------
# Core per-email analysis (shared by training, prediction and the UI)
# --------------------------------------------------------------------------
def analyze_email(subject, body, sender):
    """Return (features: dict, details: dict) for one email.

    ``features`` are the numeric model inputs (keys == FEATURE_NAMES).
    ``details`` holds human-readable evidence used by the explainer UI.
    """
    subject, body, sender = _s(subject), _s(body), _s(sender)
    text = subject + " " + body
    urls = _extract_urls(text)
    hosts = [_host(u) for u in urls]
    s_dom = _sender_domain(sender)

    brands = _brands_in_text(text)
    mismatch_brands = [b for b in brands if not _on_domain(s_dom, BRAND_DOMAINS[b])]
    lookalike_sender = [b for b in BRAND_NAMES if _imitates_brand(s_dom, b)]
    lookalike_urls = sorted({b for h in hosts for b in BRAND_NAMES if _imitates_brand(h, b)})

    url_sender_mismatch = 0
    if urls and s_dom:
        base = ".".join(s_dom.split(".")[-2:])
        url_sender_mismatch = int(any(h and not _on_domain(h, [base]) for h in hosts))

    feats = {
        "url_count": len(urls),
        "has_ip_url": int(_has_ip_url(urls)),
        "has_shortener": int(_has_shortener(urls)),
        "has_suspicious_tld": int(_has_suspicious_tld(urls)),
        "urgency_keyword_count": _count_keywords(text, URGENCY_KEYWORDS),
        "exclamation_count": text.count("!"),
        "dollar_sign_present": int("$" in text),
        "all_caps_word_count": _all_caps_word_count(text),
        "body_length": len(body),
        "subject_length": len(subject),
        "brand_sender_mismatch": int(bool(mismatch_brands)),
        "sender_suspicious_tld": int(s_dom.endswith(SUSPICIOUS_TLDS)),
        "url_brand_mismatch": int(bool(lookalike_urls)),
        "sender_lookalike": int(bool(lookalike_sender)),
        "non_https_url_count": sum(1 for u in urls if u.lower().startswith("http://")),
        "max_host_hyphens": max([h.count("-") for h in hosts], default=0),
        "credential_keyword_count": _count_keywords(text, CREDENTIAL_KEYWORDS),
        "money_keyword_count": _count_keywords(text, MONEY_KEYWORDS),
        "freemail_sender": int(_on_domain(s_dom, FREEMAIL_DOMAINS)),
        "url_sender_mismatch": url_sender_mismatch,
        "has_at_in_url": int(any("@" in u.split("//", 1)[-1].split("/", 1)[0] for u in urls)),
    }

    details = {
        "urls": [
            {
                "url": u,
                "host": h,
                "ip": bool(IPV4_REGEX.match(h)),
                "shortener": _on_domain(h, SHORTENER_DOMAINS),
                "bad_tld": h.endswith(SUSPICIOUS_TLDS),
                "insecure": u.lower().startswith("http://"),
                "lookalike": [b for b in BRAND_NAMES if _imitates_brand(h, b)],
            }
            for u, h in zip(urls, hosts)
        ],
        "sender_domain": s_dom,
        "brands": brands,
        "mismatch_brands": mismatch_brands,
        "lookalike_sender": lookalike_sender,
        "lookalike_urls": lookalike_urls,
        "urgency_hits": sorted({k for k in URGENCY_KEYWORDS if k in text.lower()}),
        "credential_hits": sorted({k for k in CREDENTIAL_KEYWORDS if k in text.lower()}),
    }
    return feats, details


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    df must contain columns: 'subject', 'body', 'sender'
    Returns a DataFrame of numeric handcrafted features (one row per email).
    """
    rows = [
        analyze_email(s, b, f)[0]
        for s, b, f in zip(df["subject"], df["body"], df["sender"])
    ]
    return pd.DataFrame(rows, index=df.index, columns=FEATURE_NAMES)


def build_feature_matrix(df, tfidf_vectorizer=None, scaler=None, fit=True):
    """
    Combines TF-IDF text features with handcrafted numeric features into
    a single sparse matrix. If fit=True, fits the vectorizer/scaler;
    otherwise reuses the ones passed in (for transforming new/test data).
    """
    text = (df["subject"].map(_s) + " " + df["body"].map(_s)).values
    handcrafted = extract_features(df)

    if fit:
        tfidf_vectorizer = TfidfVectorizer(
            max_features=1500, ngram_range=(1, 2), stop_words="english",
            sublinear_tf=True,
        )
        text_features = tfidf_vectorizer.fit_transform(text)
        scaler = StandardScaler()
        numeric_features = scaler.fit_transform(handcrafted.values)
    else:
        text_features = tfidf_vectorizer.transform(text)
        numeric_features = scaler.transform(handcrafted.values)

    combined = hstack([text_features, csr_matrix(numeric_features)]).tocsr()
    return combined, tfidf_vectorizer, scaler
