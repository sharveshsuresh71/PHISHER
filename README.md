# PhishGuard — Phishing Email Detection (ML + live 3D UI)

A Scikit-learn pipeline that classifies emails as **Phishing** or **Safe**,
now with a Flask web app and a live **WebGL (three.js)** interface: a 3D
"threat crystal" that scans, then turns green / amber / red with the verdict,
alongside a plain-English list of the red and green flags behind every score.

## Quick start

```bash
pip install -r requirements.txt
python app.py            # → http://127.0.0.1:5000   (PORT=8080 python app.py to change)
```

On first run the app trains the model automatically if the `.joblib` files are
missing. Everything (including three.js) is bundled — no CDN needed except the
optional Google Fonts. Run the tests with `python -m pytest tests`.

| Interface | How |
|---|---|
| Web UI | `python app.py` |
| JSON API | `POST /api/analyze` `{"subject","sender","body"}` → verdict, score, signals, links |
| Retrain | `python train.py` (rewrites model files, `metrics.json`, `confusion_matrix.png`) |

*Created by Sharvesh · Shark Webs*

## Intro screen

On first open of each browser session a Shark Webs intro plays (a shark fin cuts through the waves, the wordmark and “Created by Sharvesh” appear) while the app genuinely loads, then the screen splits open. Click **Skip** or press Enter/Esc to skip; it respects reduced-motion. Edit the text in `static/index.html` (`#splash`).

## Voice, websites and screenshots

- **Voice agent** — after every scan the app *speaks* a short briefing: the verdict, the biggest security risks and why each one is dangerous, then what to do. It uses your browser's built-in speech (nothing is sent anywhere); the crystal pulses with each spoken word. Auto-speak, voice and speed are on the result panel; Esc stops it.
- **Your own voice (Fish Audio, optional)** — copy `.env.example` to `.env` and set `FISH_API_KEY` (your voice ID is pre-filled). The server then speaks every briefing in your reference voice via `/api/speak`; the key never reaches the browser. Without a key it uses the browser voice. Each scan costs a few Fish credits; requests are rate-limited to 30/min per IP.
- **Website tab** — paste any address (`POST /api/analyze-url {"url": ...}`). The site is never opened; the address is judged for look-alike brand names, brand-in-subdomain tricks, raw IPs, punycode, shorteners, risky endings, `@` tricks, bait words and more.
- **Screenshots** — drop, browse or press Ctrl+V to paste an image of an email or page (`POST /api/ocr`). Text is read with Tesseract (`apt install tesseract-ocr` / `brew install tesseract` / Windows installer); if the server has none, the browser falls back to tesseract.js (needs internet). OCR can mix up 1/l and 0/O, so the extracted text is editable before re-scanning.

## What was fixed in this upgrade

- **Fake 100% accuracy** — the old dataset was a few copy-pasted templates, so train and test were near-identical. The generator now composes thousands of varied emails (no duplicates), including *hard negatives* (legit "urgent"/"password"/verification-code mails and real brand mails) and *hard positives* (link-less CEO fraud, free-mail senders, typosquats).
- **Model selection leaked the test set** — the best model was picked on test accuracy. It is now chosen by 5-fold CV on the training split only.
- **Brand matching by substring** — `irs` matched "first", `chase` matched "purchase". Now word-boundary matching, plus an official-domain map so a real `amazon.com` email is *not* flagged while `paypal-security.tk` / `paypa1.com` are.
- **URLs kept trailing punctuation** (`http://evil.tk,`), breaking TLD/IP checks; suspicious-TLD detection could also crash on odd URLs. Now parsed with `urllib`.
- **Crashes** on `None`/empty fields, and `predict_email` failing unless run from the project folder (paths are now absolute). Probabilities are plain floats instead of `np.float64`.
- New signals: look-alike sender/link domains, `@` tricks, hyphen-stuffed hosts, http links, credential and money-transfer wording, free-mail senders, link/sender mismatch.
- `features.py` docstring referenced a non-existent `model.py`; shared feature building now lives in `features.build_feature_matrix`.

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask server + JSON API |
| `webcheck.py` / `narrator.py` / `ocr.py` | Website scoring, spoken briefing text, screenshot OCR |
| `detector.py` | Loads the model, scores an email, produces the explanation |
| `static/` | Front-end: `index.html`, `css/style.css`, `js/main.js` (UI), `js/scene.js` (three.js scene), `vendor/three` (bundled three.js r160) |
| `dataset.py` | Synthetic labeled dataset generator (2,000 emails by default) |
| `features.py` | Handcrafted features + TF-IDF feature matrix |
| `train.py` | Trains Logistic Regression & Random Forest, CV-selects, evaluates, saves artifacts |
| `tests/` | pytest suite (unseen hand-written emails, URL parsing, API) |
| `emails_dataset.csv`, `metrics.json`, `confusion_matrix.png`, `*.joblib` | Generated data / artifacts |

## Training from the command line

```bash
python train.py
```

This prints accuracy/classification reports for both models, saves a
confusion matrix image, persists the trained model, and runs a demo
classification on two brand-new example emails.

## Classify a new email in your own code

```python
from train import predict_email

label, proba = predict_email(
    subject="Urgent: Verify your account",
    body="Click here to verify your account: http://fake-bank.tk/login",
    sender="alerts@fake-bank.tk",
)
print(label, proba)   # -> Phishing {'phishing': 0.98, 'safe': 0.02}
```

## Features extracted

**URL-based:** number of links, IP-address links, URL shorteners
(bit.ly, tinyurl, ...), suspicious TLDs (.ru, .tk, .xyz, .click, ...).

**Keyword/urgency-based:** counts of phrases like "verify your account",
"suspended", "click here", "final notice", "act now", "credit card", etc.

**Structural:** exclamation mark count, ALL-CAPS word count, body/subject
length, presence of dollar amounts.

**Sender-based:** brand name mentioned in the email but absent from the
sender's domain (classic spoofing signal), suspicious sender TLD.

These are combined with **TF-IDF** (unigrams + bigrams, 1500 features)
over the subject + body text, then fed into the classifier.

## Using a real-world dataset instead of the synthetic one

The synthetic dataset in `dataset.py` is intentionally template-based
so the pipeline runs end-to-end without any external files, which is
why accuracy comes out at/near 100% — the templates are cleanly
separable. For realistic performance numbers, replace `load_data()` in
`train.py` with a loader for a real corpus, e.g.:

```python
import pandas as pd

def load_data():
    df = pd.read_csv("your_real_emails.csv")   # needs: subject, body, sender, label
    df["label"] = df["label"].map({1: "phishing", 0: "safe"})  # if numeric
    df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
    return df
```

Good public sources to try: the Kaggle "Phishing Email Detection" /
"Nazario phishing corpus" datasets, or the SpamAssassin public corpus
for the "safe" class. Real-world data will have noisier, overlapping
signals, so expect accuracy in the 90–98% range rather than 100%
depending on the dataset and feature set.

## Notes / next steps

- Add more handcrafted features (e.g., DKIM/SPF pass-fail, attachment
  types, HTML-to-text ratio) if you have access to raw `.eml` files.
- Try `GridSearchCV` to tune `C` for Logistic Regression or
  `max_depth`/`n_estimators` for Random Forest.
- For production use, retrain periodically — phishing language and
  domains evolve quickly.
