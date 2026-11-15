"""
Turns an analysis result into a short spoken briefing — what the risk is,
why it is dangerous, and what to do. The browser reads this aloud.
"""

from __future__ import annotations

# signal title -> (what the attacker is doing, why it hurts)
WHY = {
    "Look-alike sender domain": "The sender's address is a copy of a trusted brand with a letter swapped. Attackers register these so the email looks genuine at a glance.",
    "Look-alike domain": "The address is a copy of a trusted brand with small changes. It is built to fool you into typing your password into a fake page.",
    "Brand / sender mismatch": "The message talks about a company but doesn't come from that company. That is the classic spoofing pattern.",
    "High-risk sender domain": "The sender's domain ending is heavily used by scammers because it is cheap and disposable.",
    "Free-mail sender": "A personal mailbox is pretending to be a business or asking for money. That is typical of boss-impersonation fraud.",
    "Link imitates a brand": "The link looks like a famous brand but leads somewhere else. Clicking could land you on a credential-stealing page.",
    "Link to a raw IP address": "Legitimate companies almost never send you to a bare numeric address. It usually means a throwaway attack server.",
    "Raw IP address": "Legitimate companies almost never ask you to log in at a bare numeric address.",
    "URL shortener": "A shortened link hides where you will really land, so you can't judge it before clicking.",
    "High-risk link domain": "A link uses a domain ending that is heavily abused for scams.",
    "High-risk domain ending": "This domain ending is heavily abused for scams and throwaway sites.",
    "'@' trick in link": "Everything before the at-sign in a web address is ignored by the browser, so attackers use it to disguise the real host.",
    "'@' trick in address": "Everything before the at-sign in a web address is ignored by the browser, so attackers use it to disguise the real host.",
    "Hyphen-stuffed domain": "Fake sites often chain words with hyphens, like paypal dash secure dash login, to look official.",
    "Insecure link": "The link isn't encrypted, so a legitimate company would not ask you to sign in there.",
    "Not encrypted (http)": "The page isn't encrypted, so anything you type could be read or changed on the way.",
    "Link domain differs from sender": "The links go to a different site than the sender's own, which is common in phishing.",
    "Urgency / pressure language": "Pressure and deadlines are used to rush you into acting before you think. It is the number one social-engineering tactic.",
    "Asks for credentials / sensitive data": "The message pushes you to hand over logins or card details. Real companies don't ask for those by email.",
    "Money-transfer wording": "It asks for payments or transfers from a personal mailbox, which is a hallmark of wire fraud.",
    "Excessive exclamation marks": "Shouty punctuation is a pressure tactic.",
    "ALL-CAPS shouting": "Capital-letter shouting is another pressure tactic.",
    "Punycode / look-alike characters": "Foreign characters can look identical to English letters, so the site appears to be a brand it isn't.",
    "Non-ASCII characters in domain": "Look-alike characters can disguise the real site name.",
    "Brand name used as bait": "A trusted name is placed in the address of an unrelated site to make it look safe.",
    "Brand hidden in subdomain": "The trusted name is only a prefix; the real website is the part right before the domain ending.",
    "Many subdomains": "Long chains of subdomains push the real domain out of view.",
    "Very long domain": "Long hostnames are used to hide the real site name.",
    "Unusual port": "Normal websites rarely run on odd network ports.",
    "Credential-bait wording": "The address is stuffed with words like login, verify and secure to look like an official account page.",
    "Very long address": "Long addresses bury tracking and redirects.",
    "Heavily encoded address": "Encoding hides the true destination.",
    "Open-redirect parameter": "The link bounces you to another site after you click, which hides the final destination.",
}

ACTIONS = {
    "PHISHING": "My advice: do not click anything, do not reply, and do not enter any details. Report it as phishing and delete it. If you already clicked or typed a password, change it right now from the official site, turn on two-factor authentication, and watch your accounts.",
    "SUSPICIOUS": "My advice: don't click the links. Open the company's official site by typing the address yourself, or call them on a number you already trust, and check there before doing anything.",
    "SAFE": "It looks safe, but nothing is ever perfect. If anything still feels off, go to the official site yourself instead of clicking.",
}


def _pct(score: float) -> str:
    return f"{round(score * 100)} percent"


def narrate(result: dict, top: int = 4) -> dict:
    """Return {'text': str, 'chunks': [str]}; chunks are sentence groups for pacing."""
    kind = "website" if result.get("kind") == "website" else "email"
    verdict = result["verdict"]
    score = result["score"]
    risks = [s for s in result["signals"] if s["kind"] == "risk"]
    goods = [s for s in result["signals"] if s["kind"] == "good"]

    chunks = []
    if verdict == "PHISHING":
        chunks.append(f"Warning. This {kind} is very likely a phishing attempt, with a risk score of {_pct(score)}.")
    elif verdict == "SUSPICIOUS":
        chunks.append(f"Be careful. This {kind} looks suspicious, with a risk score of {_pct(score)}.")
    else:
        chunks.append(f"Good news. This {kind} looks safe, with a phishing risk of only {_pct(score)}.")

    if risks:
        n = len(risks)
        chunks.append(f"I found {n} security {'risk' if n == 1 else 'risks'}." + (f" Here are the {top} biggest." if n > top else ""))
        for i, s in enumerate(risks[:top], 1):
            why = WHY.get(s["title"], s["detail"])
            chunks.append(f"{'Number ' + str(i) + '. '}{s['title']}. {_clean(s['detail'])}. {why}")
    elif goods:
        chunks.append("I found no red flags. " + _clean(goods[0]["detail"]) + ".")

    if result.get("terms") and verdict != "SAFE":
        words = ", ".join(t["term"] for t in result["terms"][:4])
        chunks.append(f"The wording also pushed the model toward phishing, especially: {words}.")

    chunks.append(ACTIONS[verdict])
    chunks = [c.replace("..", ".").strip() for c in chunks]
    return {"text": " ".join(chunks), "chunks": chunks}


def _clean(s: str) -> str:
    # make URLs / odd symbols friendlier for a speech engine
    return (s.replace("http://", "http ").replace("https://", "https ")
             .replace("/", " slash ").replace(".", " dot ").replace("-", " dash ").replace("_", " ")
             .replace("  ", " ").strip(" ."))
