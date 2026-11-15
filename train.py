"""
Phishing Email Detection — Training & Evaluation
=================================================

Pipeline:
    1. Load labeled email dataset (subject, body, sender, label)
    2. Extract handcrafted features (URLs, keywords, structure, sender)
    3. Extract TF-IDF features from the email text
    4. Combine both feature sets
    5. Pick the best classifier with 5-fold cross-validation on the TRAIN
       split only (the test split is never used for model selection)
    6. Evaluate once on the held-out test split
    7. Save trained model + vectorizer + metrics to disk for reuse
    8. Provide predict_email() for classifying brand-new emails
"""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, confusion_matrix, classification_report,
    ConfusionMatrixDisplay, roc_auc_score, precision_recall_fscore_support,
)

from dataset import build_dataset
from features import build_feature_matrix, FEATURE_NAMES  # noqa: F401  (re-exported)

RANDOM_STATE = 42
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model.joblib"
TFIDF_PATH = BASE_DIR / "tfidf_vectorizer.joblib"
SCALER_PATH = BASE_DIR / "feature_scaler.joblib"
METRICS_PATH = BASE_DIR / "metrics.json"
EXPLAINER_PATH = BASE_DIR / "explainer.joblib"
CM_PATH = BASE_DIR / "confusion_matrix.png"
DATASET_PATH = BASE_DIR / "emails_dataset.csv"


def load_data(n_per_class=1000):
    rows = build_dataset(n_per_class=n_per_class, seed=RANDOM_STATE)
    return pd.DataFrame(rows, columns=["subject", "body", "sender", "label"])


def plot_confusion_matrix(y_true, y_pred, labels, out_path):
    import matplotlib  # only needed for training, not for serving
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    fig, ax = plt.subplots(figsize=(5.5, 5))
    disp.plot(ax=ax, cmap="Blues", colorbar=True, values_format="d")
    ax.set_title("Phishing Detection — Confusion Matrix")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    return cm


def main(verbose=True):
    log = print if verbose else (lambda *a, **k: None)
    log("=" * 60)
    log("PHISHING EMAIL DETECTION MODEL")
    log("=" * 60)

    # 1. Load data (and keep a copy on disk for inspection)
    df = load_data()
    df.to_csv(DATASET_PATH, index=False)
    log(f"\nDataset loaded: {len(df)} emails "
        f"({(df['label'] == 'phishing').sum()} phishing, "
        f"{(df['label'] == 'safe').sum()} safe)")

    # 2. Train/test split (stratified to keep class balance)
    train_df, test_df = train_test_split(
        df, test_size=0.25, random_state=RANDOM_STATE, stratify=df["label"]
    )
    log(f"Train set: {len(train_df)} | Test set: {len(test_df)}")

    # 3. Build combined feature matrices (fit on train only)
    X_train, tfidf, scaler = build_feature_matrix(train_df, fit=True)
    X_test, _, _ = build_feature_matrix(
        test_df, tfidf_vectorizer=tfidf, scaler=scaler, fit=False
    )
    y_train = train_df["label"].values
    y_test = test_df["label"].values

    # 4. Select the best model by cross-validated F1 on the TRAIN split
    candidates = {
        "Logistic Regression": LogisticRegression(
            max_iter=2000, random_state=RANDOM_STATE, C=2.0
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=300, random_state=RANDOM_STATE, n_jobs=-1
        ),
    }
    y_train_bin = (y_train == "phishing").astype(int)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    results = {}
    for name, clf in candidates.items():
        cv_f1 = cross_val_score(clf, X_train, y_train_bin, cv=cv, scoring="f1").mean()
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        acc = accuracy_score(y_test, preds)
        results[name] = {"model": clf, "preds": preds, "accuracy": acc, "cv_f1": cv_f1}
        log(f"\n--- {name} ---   (5-fold CV F1 on train: {cv_f1:.4f})")
        log(f"Test accuracy: {acc:.4f}")
        log(classification_report(y_test, preds, digits=3))

    best_name = max(results, key=lambda k: results[k]["cv_f1"])
    best_model = results[best_name]["model"]
    best_preds = results[best_name]["preds"]
    log(f"\n>>> Best model (by CV): {best_name} "
        f"(test accuracy = {results[best_name]['accuracy']:.4f})")

    # 5. Confusion matrix + metrics for the best model
    labels = sorted(df["label"].unique())  # ['phishing', 'safe']
    cm = plot_confusion_matrix(y_test, best_preds, labels, out_path=CM_PATH)
    log("\nConfusion Matrix (rows=actual, cols=predicted):")
    log(pd.DataFrame(cm, index=[f"actual_{l}" for l in labels],
                     columns=[f"pred_{l}" for l in labels]))

    y_test_bin = (y_test == "phishing").astype(int)
    phishing_idx = list(best_model.classes_).index("phishing")
    proba = best_model.predict_proba(X_test)[:, phishing_idx]
    auc = roc_auc_score(y_test_bin, proba)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_test_bin, (best_preds == "phishing").astype(int), average="binary"
    )
    log(f"\nROC-AUC: {auc:.4f}")

    # 6. Top features for interpretability
    names = list(tfidf.get_feature_names_out()) + FEATURE_NAMES
    if hasattr(best_model, "feature_importances_"):
        weights = best_model.feature_importances_
    else:
        weights = np.abs(best_model.coef_[0])
    top_idx = np.argsort(weights)[-15:][::-1]
    log("\nTop 15 most important features:")
    for i in top_idx:
        log(f"  {names[i]:<30s} {weights[i]:.4f}")

    # 7. Persist model + preprocessing objects + metrics
    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(tfidf, TFIDF_PATH)
    joblib.dump(scaler, SCALER_PATH)
    # A linear model fit on the same features gives *directional* word weights
    # (which words push toward phishing) for the UI, whichever model won above.
    explainer = LogisticRegression(max_iter=2000, random_state=RANDOM_STATE, C=1.0).fit(X_train, y_train)
    joblib.dump(explainer, EXPLAINER_PATH)
    metrics = {
        "model": best_name,
        "accuracy": round(float(results[best_name]["accuracy"]), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(auc), 4),
        "cv_f1": round(float(results[best_name]["cv_f1"]), 4),
        "n_emails": int(len(df)),
        "n_train": int(len(train_df)),
        "n_test": int(len(test_df)),
        "n_features": int(X_train.shape[1]),
        "confusion": cm.tolist(),
        "labels": labels,
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    log(f"\nSaved: {MODEL_PATH.name}, {TFIDF_PATH.name}, {SCALER_PATH.name}, "
        f"{METRICS_PATH.name}, {CM_PATH.name}")

    return best_model, tfidf, scaler


def predict_email(subject, body, sender, model=None, tfidf=None, scaler=None):
    """
    Classify a single email. Returns (label, probabilities) where label is
    'Phishing' or 'Safe' and probabilities is {'phishing': float, 'safe': float}.
    Missing/None fields are treated as empty strings.
    """
    if model is None:
        model = joblib.load(MODEL_PATH)
    if tfidf is None:
        tfidf = joblib.load(TFIDF_PATH)
    if scaler is None:
        scaler = joblib.load(SCALER_PATH)

    single_df = pd.DataFrame([{"subject": subject, "body": body, "sender": sender}])
    X, _, _ = build_feature_matrix(single_df, tfidf_vectorizer=tfidf, scaler=scaler, fit=False)
    pred = model.predict(X)[0]
    proba = {str(c): float(p) for c, p in zip(model.classes_, model.predict_proba(X)[0])}
    return ("Phishing" if pred == "phishing" else "Safe"), proba


DEMO_EMAILS = [
    dict(
        subject="Urgent: Verify your PayPal account immediately",
        body="Your account has been limited. Click here to verify: "
             "http://paypal-verify-account.com/login. Failure to act "
             "within 24 hours will result in permanent suspension!!!",
        sender="support@paypal-security.tk",
    ),
    dict(
        subject="Team lunch this Friday",
        body="Hey everyone, let's grab lunch this Friday at noon to "
             "celebrate the product launch. Let me know if you can make it!",
        sender="alex@company.com",
    ),
]

if __name__ == "__main__":
    model, tfidf, scaler = main()

    print("\n" + "=" * 60)
    print("DEMO: Classifying new, unseen emails")
    print("=" * 60)
    for email in DEMO_EMAILS:
        label, proba = predict_email(**email, model=model, tfidf=tfidf, scaler=scaler)
        print(f"\nSubject: {email['subject']}")
        print(f"Prediction: {label}")
        print(f"Probabilities: { {k: round(v, 3) for k, v in proba.items()} }")
