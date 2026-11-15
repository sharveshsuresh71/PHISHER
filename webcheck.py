"""
Website / URL risk analysis (offline heuristics — the site is never visited).

Returns the same shape as ``Detector.analyze`` so the UI and the voice
narrator can treat emails and websites identically.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, unquote

from features import (
    BRAND_DOMAINS, BRAND_NAMES, IPV4_REGEX, SHORTENER_DOMAINS, SUSPICIOUS_TLDS,
    URL_REGEX, TRAILING_PUNCT, _imitates_brand, _on_domain,
)

MAX_URL_LEN = 4096
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}
_LURE_WORDS = ["login", "signin", "log-in", "verify", "verification", "secure", "account",
               "update", "confirm", "wallet", "banking", "password", "billing", "suspend", "unlock", "recover"]
_DOMAIN_LIKE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?:/[^\s]*)?", re.I)


def normalize(raw: str) -> str:
    """Trim, strip trailing punctuation and add a scheme if missing."""
    u = (raw or "").strip().strip("<>\"'").rstrip(TRAILING_PUNCT)
    u = u.split()[0] if u.split() else ""
    if u and "://" not in u:
        u = "http://" + u  # scheme-less input: treat as unverified (http)
    return u


def find_url(text: str) -> str:
    """Pull the first URL (or bare domain) out of free text, e.g. OCR output."""
    m = URL_REGEX.search(text or "")
    if m:
        return m.group(0).rstrip(TRAILING_PUNCT)
    m = _DOMAIN_LIKE.search(text or "")
    return m.group(0).rstrip(TRAILING_PUNCT) if m else ""


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze_url(raw: str) -> dict:
    url = normalize(raw)[:MAX_URL_LEN]
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        host, port, p = "", None, urlparse("")
    if not host or "." not in host and not IPV4_REGEX.match(host):
        raise ValueError("That doesn't look like a web address. Try something like https://example.com/login")

    reg = _registrable(host)
    labels = host.split(".")
    subs = labels[:-len(reg.split("."))] if not IPV4_REGEX.match(host) else []
    path_q = unquote((p.path or "") + "?" + (p.query or "")).lower()
    sigs: list[tuple[str, str, str, float]] = []  # kind, title, detail, weight/strength

    def risk(title, detail, w):
        sigs.append(("risk", title, detail, w))

    # --- brand impersonation (the strongest signal) ---
    imitated = [b for b in BRAND_NAMES if _imitates_brand(host, b)]
    if imitated:
        risk("Look-alike domain", f"{host} imitates {', '.join(imitated)} but isn't an official domain", 0.95)
    # brand appears only in the path or subdomain of a different site
    path_brands = [b for b in BRAND_NAMES if re.search(r"\b" + re.escape(b.replace(" ", "")) + r"\b", path_q.replace("-", "").replace("/", " "))
                   and not _on_domain(host, BRAND_DOMAINS[b])]
    if path_brands and not imitated:
        risk("Brand name used as bait", f"The address mentions {', '.join(path_brands)} but the site is {reg}", 0.6)

    # --- host tricks ---
    if IPV4_REGEX.match(host):
        risk("Raw IP address", "Real companies almost never ask you to log in at a bare IP", 0.9)
    if "xn--" in host:
        risk("Punycode / look-alike characters", "The domain may use foreign letters that mimic English ones", 0.85)
    elif any(ord(c) > 127 for c in host):
        risk("Non-ASCII characters in domain", "Visually similar characters can disguise the real site", 0.8)
    if _on_domain(host, SHORTENER_DOMAINS):
        risk("URL shortener", "The real destination is hidden behind a short link", 0.65)
    tld = "." + labels[-1]
    if host.endswith(SUSPICIOUS_TLDS):
        risk("High-risk domain ending", f"{tld} is heavily used for scams and throwaway sites", 0.7)
    if "@" in (p.netloc or ""):
        risk("'@' trick in address", "Text before '@' is ignored by the browser and used to disguise the host", 0.9)
    if host.count("-") >= 2:
        risk("Hyphen-stuffed domain", f"{host.count('-')} hyphens — a pattern common in fake sites", 0.5)
    if len(subs) >= 3:
        risk("Many subdomains", f"{len(subs)} subdomain levels can bury the real domain ({reg})", 0.5)
    elif subs and any(_imitates_brand(s, b) or s == b.replace(" ", "") for s in subs for b in BRAND_NAMES) \
            and not any(_on_domain(host, d) for ds in BRAND_DOMAINS.values() for d in ds):
        risk("Brand hidden in subdomain", f"The brand name is only a subdomain — the real site is {reg}", 0.9)
    if len(host) > 40:
        risk("Very long domain", f"{len(host)} characters — long hosts are used to hide the real name", 0.4)
    if port and port not in (80, 443):
        risk("Unusual port", f"Connects on port {port}", 0.45)

    # --- transport / path ---
    if url.lower().startswith("http://"):
        risk("Not encrypted (http)", "Anything you type could be read or altered in transit", 0.4)
    lures = [w for w in _LURE_WORDS if w in path_q or w in host]
    if lures and (sigs or len(lures) >= 3):
        risk("Credential-bait wording", "Address contains: " + ", ".join(lures[:5]), min(0.3 + 0.1 * len(lures), 0.6))
    if len(url) > 120:
        risk("Very long address", f"{len(url)} characters of tracking / redirect clutter", 0.3)
    if re.search(r"%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}", (p.path or "") + (p.query or ""), re.I):
        risk("Heavily encoded address", "Percent-encoding can hide the true destination", 0.4)
    if re.search(r"(?:url|redirect|redir|next|goto|target|dest)=https?", url, re.I):
        risk("Open-redirect parameter", "Link forwards you on to another site after clicking", 0.55)

    # --- trust signals ---
    good = []
    official = [b for b, ds in BRAND_DOMAINS.items() if _on_domain(host, ds)]
    if official:
        good.append(("good", "Official brand domain", f"{reg} is a genuine {', '.join(official)} domain", 0.85))
    if url.lower().startswith("https://"):
        good.append(("good", "Encrypted (https)", "Connection is encrypted — though scammers use https too", 0.3))
    if not sigs:
        good.append(("good", "No phishing indicators", "No red flags in the address itself", 0.7))

    # noisy-OR of risk weights → probability-like score
    keep = 1.0
    for _, _, _, w in sigs:
        keep *= 1 - 0.8 * w
    score = 1 - keep
    if official and not imitated:
        score *= 0.25
    score = round(min(max(score, 0.01 if not sigs else 0.08), 0.99), 4)

    verdict = "PHISHING" if score >= 0.70 else "SUSPICIOUS" if score >= 0.35 else "SAFE"
    signals = [{"kind": k, "title": t, "detail": d, "strength": round(min(max(s, 0.05), 1.0), 2)}
               for k, t, d, s in sorted(sigs, key=lambda x: -x[3]) + good]

    return {
        "verdict": verdict,
        "score": score,
        "probabilities": {"phishing": score, "safe": round(1 - score, 4)},
        "signals": signals,
        "urls": [{
            "url": url, "host": host, "ip": bool(IPV4_REGEX.match(host)),
            "shortener": _on_domain(host, SHORTENER_DOMAINS), "bad_tld": host.endswith(SUSPICIOUS_TLDS),
            "insecure": url.lower().startswith("http://"), "lookalike": imitated,
        }],
        "terms": [],
        "model": "URL heuristics",
        "kind": "website",
        "target": host,
    }
