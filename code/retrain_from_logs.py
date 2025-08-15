# === Metrics report helper for results_eval.html ===
# Drop-in for retrain_from_logs.py
from __future__ import annotations

import json, os, math, datetime
from typing import Sequence, Optional, Dict, Any, Tuple, List




# Matplotlib only for saving PNGs (no GUI needed)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    roc_auc_score
)

# --- Step 1: Load your real SDN traffic log ---
df = pd.read_csv("flow_log.csv", header=None, names=[
    "timestamp", "src_ip", "dst_ip", "proto", "pkt_len","src_port","dst_port", "ml", "mud"
])

# --- Step 2: Drop incomplete (non-IP) rows ---
df = df[df["src_ip"] != "N/A"]
df = df[df["dst_ip"] != "N/A"]

# --- Step 3: Create a label column (you can customize this logic!) ---
# Define benign/malicious rule
def label_row(row):
    try:
        proto = row["proto"]
        pkt_len = row["pkt_len"]
        dst_port = row["dst_port"]
        src_port = row["src_port"]

        # ICMP pings
        if proto == 1 and 64 <= pkt_len <= 128:
            return 0  # benign

        #  iperf3 (TCP to port 5201 with large packets)
        if proto == 6 and dst_port == 5201 and pkt_len > 1000:
            return 0  # benign

        # Legit TCP services (web, SSH, DNS)
        if proto == 6 and dst_port in [22, 80, 443, 53] and pkt_len > 60:
            return 0  # benign

        # Small TCP packets to legit services (ACKs, SYN-ACKs)
        if proto == 6 and dst_port in [22, 80, 443, 53] and pkt_len >= 40:
            return 0  # benign

        # UDP DNS or small bursts under control
        if proto == 17 and dst_port == 53 and pkt_len < 300:
            return 0  # benign
        
        

        # SYN flood or TCP scan: small TCP packets to unknown ports
        if proto == 6 and pkt_len < 80 and dst_port not in [22, 80, 443, 5201, 53]:
            return 1  # malicious

        # Large UDP packets — flood attempts
        if proto == 17 and pkt_len < 1200:
            return 1  # malicious

        # Random UDP to unknown ports
        if proto == 17 and dst_port not in [53, 5201]:
            return 1  # malicious

        # Default: anything unrecognized is malicious
        return 1
    except:
        return 1  # Fail-safe: label as malicious



df["label"] = df.apply(label_row, axis=1)

# --- Step 4: Extract relevant features ---
X = df[["proto", "pkt_len", "src_port", "dst_port"]]
y = df["label"]

# --- Step 5: Train/test split ---
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# --- Step 6: Train model ---
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# --- Step 7: Evaluate ---
print("📊 Classification Report:")
print(classification_report(y_test, model.predict(X_test)))

# --- Step 8: Save model ---
joblib.dump(model, "rf_model.pkl")
print("✅ New model saved as rf_model.pkl")











def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def _to_list(a: Any) -> List:
    return a.tolist() if hasattr(a, "tolist") else list(a)


def emit_metrics_report(
    y_true: Sequence,
    y_pred: Optional[Sequence] = None,
    y_proba: Optional[Sequence[float]] = None,
    *,
    labels: Sequence[str] = ("benign", "malicious"),
    positive_label: Optional[str] = "malicious",
    threshold: Optional[float] = None,
    split: Optional[Dict[str, Any]] = None,
    version: Optional[str] = None,
    out_json: str = "artifacts/metrics_report.json",
    cm_png: Optional[str] = "artifacts/confusion_matrix.png",
    roc_png: Optional[str] = "artifacts/roc_curve.png"
) -> Dict[str, Any]:
    """
    Build and save a metrics JSON + images in the exact schema expected by results_eval.html.

    Args:
        y_true: iterable of ground-truth labels (class names or ints).
        y_pred: iterable of predicted labels; if None and y_proba+threshold are given, it will be derived.
        y_proba: iterable of P(positive) probabilities; needed for AUC and for deriving y_pred when threshold is set.
        labels: ordered class names used by the model/report.
        positive_label: which class is considered "positive" (default "malicious"). Set to None to disable AUC.
        threshold: if provided and y_proba is given, we compute y_pred = (proba >= threshold).
        split: optional dict like {"train": 0.7, "val": 0.15, "test": 0.15}.
        version: model version string (e.g., "rf_model_v1.0.0").
        out_json: where to write the JSON report.
        cm_png: where to save the confusion matrix PNG (set None to skip).
        roc_png: where to save the ROC curve PNG (set None to skip).

    Returns:
        The report dict that was written to JSON.
    """
    y_true = np.asarray(y_true)
    if y_pred is None and y_proba is not None and threshold is not None:
        y_pred = np.where(np.asarray(y_proba) >= float(threshold), positive_label, labels[0])
    y_pred = np.asarray(y_pred) if y_pred is not None else None

    # Map labels to indices (for metrics consistency)
    label_list = list(labels)
    label_to_idx = {c: i for i, c in enumerate(label_list)}

    # Convert y_true/y_pred to indices
    def to_idx(arr):
        if arr is None:
            return None
        if np.issubdtype(np.asarray(arr).dtype, np.number):
            return np.asarray(arr, dtype=int)
        return np.asarray([label_to_idx[x] for x in arr], dtype=int)

    y_true_i = to_idx(y_true)
    y_pred_i = to_idx(y_pred) if y_pred is not None else None

    # Accuracy
    acc = float(accuracy_score(y_true_i, y_pred_i)) if y_pred_i is not None else float("nan")

    # Per-class & averaged metrics
    if y_pred_i is not None:
        prec_c, rec_c, f1_c, support_c = precision_recall_fscore_support(
            y_true_i, y_pred_i, labels=list(range(len(label_list))), zero_division=0
        )
        # Macro/weighted
        prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(
            y_true_i, y_pred_i, average="macro", zero_division=0
        )
        prec_weighted, rec_weighted, f1_weighted, _ = precision_recall_fscore_support(
            y_true_i, y_pred_i, average="weighted", zero_division=0
        )
    else:
        # If only proba given (and no threshold), we can still compute AUC below
        # but not PR/Recall/F1 without hard predictions.
        prec_c = rec_c = f1_c = support_c = np.full(len(label_list), np.nan)
        prec_macro = rec_macro = f1_macro = np.nan
        prec_weighted = rec_weighted = f1_weighted = np.nan

    # Confusion matrix (for binary case or generalized if 2 classes)
    tn = fp = fn = tp = None
    if y_pred_i is not None and len(label_list) == 2:
        cm = confusion_matrix(y_true_i, y_pred_i, labels=[0, 1])
        tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))
    elif y_pred_i is not None:
        # Multi-class: we can still build a 2x2 by collapsing to positive vs. rest if requested
        if positive_label is not None and positive_label in label_to_idx:
            pos = label_to_idx[positive_label]
            y_true_pos = (y_true_i == pos).astype(int)
            y_pred_pos = (y_pred_i == pos).astype(int)
            cm = confusion_matrix(y_true_pos, y_pred_pos, labels=[0, 1])
            tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))

    # AUC (needs probabilities and a positive class)
    auc = None
    if y_proba is not None and positive_label is not None and positive_label in label_to_idx:
        pos = label_to_idx[positive_label]
        # y_true binary for positive label
        y_true_pos = (y_true_i == pos).astype(int)
        try:
            auc = float(roc_auc_score(y_true_pos, np.asarray(y_proba)))
        except Exception:
            auc = None

    # JSON dicts
    precision_dict = {label_list[i]: (None if math.isnan(prec_c[i]) else float(prec_c[i])) for i in range(len(label_list))}
    recall_dict    = {label_list[i]: (None if math.isnan(rec_c[i])  else float(rec_c[i]))  for i in range(len(label_list))}
    f1_dict        = {label_list[i]: (None if math.isnan(f1_c[i])    else float(f1_c[i]))  for i in range(len(label_list))}

    precision_dict["macro"]   = None if math.isnan(prec_macro)   else float(prec_macro)
    precision_dict["weighted"]= None if math.isnan(prec_weighted) else float(prec_weighted)
    recall_dict["macro"]      = None if math.isnan(rec_macro)    else float(rec_macro)
    recall_dict["weighted"]   = None if math.isnan(rec_weighted) else float(rec_weighted)
    f1_dict["macro"]          = None if math.isnan(f1_macro)     else float(f1_macro)
    f1_dict["weighted"]       = None if math.isnan(f1_weighted)  else float(f1_weighted)

    support_dict = {label_list[i]: int(support_c[i]) if not math.isnan(support_c[i]) else None for i in range(len(label_list))}

    report = {
        "version": version or "rf_model",
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "labels": label_list,
        "accuracy": None if math.isnan(acc) else float(acc),
        "precision": precision_dict,
        "recall": recall_dict,
        "f1": f1_dict,
        "auc": auc,
        "threshold": threshold,
        "confusion_matrix": None if tn is None else {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "split": split or {},
        "class_support": support_dict
    }

    # Save JSON
    _ensure_dir(out_json)
    with open(out_json, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[metrics] wrote JSON → {out_json}")

    # Optional: save confusion matrix image
    if cm_png is not None and tn is not None:
        _ensure_dir(cm_png)
        fig, ax = plt.subplots(figsize=(4, 3))
        cm_mat = np.array([[tn, fp], [fn, tp]])
        im = ax.imshow(cm_mat, cmap="Blues")
        ax.figure.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
        ax.set_xticks([0, 1], labels=["Benign", "Malicious"])
        ax.set_yticks([0, 1], labels=["Benign", "Malicious"])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        for (i, j), v in np.ndenumerate(cm_mat):
            ax.text(j, i, str(v), ha="center", va="center", fontsize=11)
        ax.set_title("Confusion Matrix")
        plt.tight_layout()
        plt.savefig(cm_png, dpi=150)
        plt.close(fig)
        print(f"[metrics] wrote CM image → {cm_png}")

    # Optional: ROC curve (needs proba + positive_label)
    if roc_png is not None and y_proba is not None and positive_label in label_to_idx:
        _ensure_dir(roc_png)
        pos = label_to_idx[positive_label]
        y_true_pos = (y_true_i == pos).astype(int)
        try:
            from sklearn.metrics import roc_curve
            fpr, tpr, _ = roc_curve(y_true_pos, np.asarray(y_proba))
            fig2, ax2 = plt.subplots(figsize=(4, 3))
            ax2.plot(fpr, tpr, lw=2)
            ax2.plot([0, 1], [0, 1], ls="--", lw=1)
            ax2.set_xlabel("FPR")
            ax2.set_ylabel("TPR")
            ax2.set_title("ROC Curve")
            plt.tight_layout()
            plt.savefig(roc_png, dpi=150)
            plt.close(fig2)
            print(f"[metrics] wrote ROC image → {roc_png}")
        except Exception as e:
            print(f"[metrics] ROC plot failed: {e}")

    return report






# 1) Get predictions on your test split
y_pred = model.predict(X_test)

# If your model supports probabilities, grab P(malicious)
y_proba = None
if hasattr(model, "predict_proba"):
    y_proba = model.predict_proba(X_test)[:, 1]

# 2) Map numeric labels -> nice names (optional but looks better on the site)
IDX_TO_NAME = {0: "benign", 1: "malicious"}

def _to_named(arr):
    # handles numpy arrays or lists
    return [IDX_TO_NAME[int(x)] for x in arr]

y_true_named = _to_named(y_test)
y_pred_named = _to_named(y_pred)

# 3) Pick an operating threshold (only used if y_proba is available)
TAU = 0.70

# 4) Emit the JSON + images for results_eval.html
#    (This calls the helper you pasted earlier in the file.)
emit_metrics_report(
    y_true=y_true_named,
    y_pred=y_pred_named,
    y_proba=y_proba,                 # can be None if your model has no predict_proba
    labels=("benign", "malicious"),
    positive_label="malicious",
    threshold=TAU,
    split={"train": 0.70, "val": 0.15, "test": 0.15},  # adjust if different
    version="rf_model_v1.0.0",
    out_json="artifacts/metrics_report.json",
    cm_png="artifacts/confusion_matrix.png",
    roc_png="artifacts/roc_curve.png"
)

print("✅ metrics_report.json + images written under ./artifacts/")