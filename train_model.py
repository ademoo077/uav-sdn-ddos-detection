#!/usr/bin/env python3
"""
================================================================
  UAV-SDN DDoS Detection — Entraînement des modèles ML
  ============================================================
  Entraîne et compare : Random Forest, SVM, LSTM (réseau de neurones)
  Génère un dataset synthétique réaliste si aucun fichier CSV n'existe.
  Sauvegarde le modèle ensemble dans models/ensemble_model.pkl

  USAGE :
    python train_model.py                    # génère + entraîne
    python train_model.py --csv mon_data.csv # utilise un vrai dataset
    python train_model.py --evaluate         # évaluation détaillée
================================================================
"""

import os, argparse, time, pickle, json
import numpy as np
import pandas as pd
from pathlib import Path
from lstm_wrapper import LSTMWrapper   # ← module séparé pour pickle

# ─── CONFIG ────────────────────────────────────────────────────
FEATURES = ["pps", "src_entropy", "syn_ratio", "udp_ratio",
            "icmp_ratio", "unique_srcs", "avg_pkt_size", "flow_count"]
LABEL    = "label"          # 0 = normal, 1 = DDoS
MODEL_DIR = "models"
RANDOM_STATE = 42
# ───────────────────────────────────────────────────────────────


# ══════════════════════════════════════════════════════════════
#  DATASET SYNTHÉTIQUE
# ══════════════════════════════════════════════════════════════
def generate_dataset(n_normal: int = 5000, n_attack: int = 5000) -> pd.DataFrame:
    """
    Génère un dataset réaliste simulant le trafic UAV-SDN.
    Trafic normal : faible pps, haute entropie, faible SYN.
    Trafic DDoS   : fort pps, faible entropie, fort SYN/UDP/ICMP.
    """
    rng = np.random.default_rng(RANDOM_STATE)

    # --- TRAFIC NORMAL ---
    normal = {
        "pps":          rng.normal(150, 60, n_normal).clip(10, 800),
        "src_entropy":  rng.normal(0.75, 0.12, n_normal).clip(0.4, 1.0),
        "syn_ratio":    rng.normal(0.03, 0.02, n_normal).clip(0, 0.15),
        "udp_ratio":    rng.normal(0.25, 0.10, n_normal).clip(0, 0.6),
        "icmp_ratio":   rng.normal(0.05, 0.03, n_normal).clip(0, 0.2),
        "unique_srcs":  rng.integers(3, 15, n_normal).astype(float),
        "avg_pkt_size": rng.normal(512, 180, n_normal).clip(64, 1500),
        "flow_count":   rng.integers(5, 40, n_normal).astype(float),
        "label":        np.zeros(n_normal, dtype=int),
    }

    # --- TRAFIC DDoS (types multiples) ---
    # UDP Flood
    n_udp = n_attack // 3
    udp_flood = {
        "pps":          rng.normal(2500, 600, n_udp).clip(1000, 5000),
        "src_entropy":  rng.normal(0.18, 0.10, n_udp).clip(0, 0.4),
        "syn_ratio":    rng.normal(0.02, 0.02, n_udp).clip(0, 0.1),
        "udp_ratio":    rng.normal(0.90, 0.06, n_udp).clip(0.7, 1.0),
        "icmp_ratio":   rng.normal(0.01, 0.01, n_udp).clip(0, 0.05),
        "unique_srcs":  rng.normal(120, 40, n_udp).clip(1, 254),
        "avg_pkt_size": rng.normal(64, 10, n_udp).clip(60, 150),
        "flow_count":   rng.integers(50, 200, n_udp).astype(float),
        "label":        np.ones(n_udp, dtype=int),
    }

    # SYN Flood
    n_syn = n_attack // 3
    syn_flood = {
        "pps":          rng.normal(1800, 500, n_syn).clip(800, 4000),
        "src_entropy":  rng.normal(0.25, 0.12, n_syn).clip(0, 0.5),
        "syn_ratio":    rng.normal(0.80, 0.10, n_syn).clip(0.5, 1.0),
        "udp_ratio":    rng.normal(0.05, 0.03, n_syn).clip(0, 0.2),
        "icmp_ratio":   rng.normal(0.02, 0.01, n_syn).clip(0, 0.1),
        "unique_srcs":  rng.normal(80, 30, n_syn).clip(1, 254),
        "avg_pkt_size": rng.normal(60, 5, n_syn).clip(40, 100),
        "flow_count":   rng.integers(60, 250, n_syn).astype(float),
        "label":        np.ones(n_syn, dtype=int),
    }

    # ICMP Flood
    n_icmp = n_attack - n_udp - n_syn
    icmp_flood = {
        "pps":          rng.normal(2000, 700, n_icmp).clip(500, 4500),
        "src_entropy":  rng.normal(0.20, 0.08, n_icmp).clip(0, 0.4),
        "syn_ratio":    rng.normal(0.01, 0.01, n_icmp).clip(0, 0.05),
        "udp_ratio":    rng.normal(0.02, 0.02, n_icmp).clip(0, 0.1),
        "icmp_ratio":   rng.normal(0.88, 0.08, n_icmp).clip(0.6, 1.0),
        "unique_srcs":  rng.normal(60, 25, n_icmp).clip(1, 200),
        "avg_pkt_size": rng.normal(64, 8, n_icmp).clip(28, 128),
        "flow_count":   rng.integers(40, 180, n_icmp).astype(float),
        "label":        np.ones(n_icmp, dtype=int),
    }

    frames = [pd.DataFrame(d) for d in [normal, udp_flood, syn_flood, icmp_flood]]
    df = pd.concat(frames, ignore_index=True)
    df = df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    print(f"Dataset généré : {len(df)} échantillons "
          f"({df[LABEL].sum()} attaques, {(df[LABEL]==0).sum()} normal)")
    return df


# ══════════════════════════════════════════════════════════════
#  ENTRAÎNEMENT
# ══════════════════════════════════════════════════════════════
def train_all(df: pd.DataFrame):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.svm import SVC
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (classification_report, confusion_matrix,
                                  roc_auc_score, f1_score)
    from sklearn.pipeline import Pipeline

    X = df[FEATURES].values
    y = df[LABEL].values
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y)

    results = {}

    # ── 1. Random Forest ────────────────────────────────────────
    print("\n" + "="*60)
    print("  1/3  RANDOM FOREST")
    print("="*60)
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=10,
        min_samples_split=5, class_weight="balanced",
        n_jobs=-1, random_state=RANDOM_STATE
    )
    rf.fit(X_tr, y_tr)
    rf_time = time.time() - t0
    rf_prob = rf.predict_proba(X_te)[:, 1]
    rf_pred = rf.predict(X_te)
    results["RandomForest"] = {
        "model": rf,
        "train_time": rf_time,
        "metrics": _metrics(y_te, rf_pred, rf_prob, "Random Forest"),
        "feature_importance": dict(zip(FEATURES,
                                       rf.feature_importances_.tolist()))
    }

    # ── 2. SVM ──────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  2/3  SVM (RBF kernel)")
    print("="*60)
    t0 = time.time()
    svm_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("svm",    SVC(kernel="rbf", C=10, gamma="scale",
                       probability=True, class_weight="balanced",
                       random_state=RANDOM_STATE))
    ])
    svm_pipe.fit(X_tr, y_tr)
    svm_time = time.time() - t0
    svm_prob = svm_pipe.predict_proba(X_te)[:, 1]
    svm_pred = svm_pipe.predict(X_te)
    results["SVM"] = {
        "model": svm_pipe,
        "train_time": svm_time,
        "metrics": _metrics(y_te, svm_pred, svm_prob, "SVM"),
    }

    # ── 3. LSTM ─────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  3/3  LSTM (réseau de neurones)")
    print("="*60)
    lstm_result = _train_lstm(X_tr, y_tr, X_te, y_te)
    results["LSTM"] = lstm_result

    # ── Résumé comparatif ────────────────────────────────────────
    _print_comparison(results)

    # ── Sauvegarde ───────────────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)
    models_to_save = {name: r["model"] for name, r in results.items()}
    pkl_path = os.path.join(MODEL_DIR, "ensemble_model.pkl")
    with open(pkl_path, "wb") as f:
        pickle.dump(models_to_save, f)
    print(f"\n✓ Modèles sauvegardés → {pkl_path}")

    # Sauvegarder les métriques JSON pour le dashboard
    metrics_summary = {
        name: {k: v for k, v in r["metrics"].items()
               if k not in ("confusion_matrix",)}
        for name, r in results.items()
    }
    metrics_summary["trained_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    metrics_summary["dataset_size"] = len(df)
    metrics_summary["features"] = FEATURES
    json_path = os.path.join(MODEL_DIR, "metrics.json")
    with open(json_path, "w") as f:
        json.dump(metrics_summary, f, indent=2)
    print(f"✓ Métriques sauvegardées → {json_path}")

    return results


def _train_lstm(X_tr, y_tr, X_te, y_te):
    """Entraîne un LSTM avec wrapper sklearn via Keras."""
    try:
        import tensorflow as tf
        from tensorflow.keras.models import Sequential
        from tensorflow.keras.layers import (LSTM, Dense, Dropout,
                                              Reshape, BatchNormalization)
        from tensorflow.keras.callbacks import EarlyStopping
        from sklearn.preprocessing import StandardScaler

        scaler = StandardScaler()
        X_tr_s = scaler.fit_transform(X_tr)
        X_te_s = scaler.transform(X_te)

        # Reshape pour LSTM : (samples, timesteps=1, features)
        X_tr_lstm = X_tr_s.reshape(-1, 1, len(FEATURES))
        X_te_lstm = X_te_s.reshape(-1, 1, len(FEATURES))

        model = Sequential([
            LSTM(64, input_shape=(1, len(FEATURES)), return_sequences=True),
            Dropout(0.3),
            LSTM(32),
            Dropout(0.2),
            BatchNormalization(),
            Dense(16, activation="relu"),
            Dense(1, activation="sigmoid")
        ])
        model.compile(optimizer="adam",
                       loss="binary_crossentropy",
                       metrics=["accuracy"])
        t0 = time.time()
        model.fit(X_tr_lstm, y_tr,
                  epochs=30, batch_size=128,
                  validation_split=0.1,
                  callbacks=[EarlyStopping(patience=5,
                                           restore_best_weights=True)],
                  verbose=1)
        train_time = time.time() - t0

        proba = model.predict(X_te_lstm, verbose=0).flatten()
        pred  = (proba > 0.5).astype(int)

        return {
            "model":      LSTMWrapper(model, scaler, len(FEATURES)),
            "train_time": train_time,
            "metrics":    _metrics(y_te, pred, proba, "LSTM"),
        }

    except ImportError:
        print("  ⚠ TensorFlow non installé — LSTM ignoré")
        print("  pip install tensorflow")
        # Fallback : MLP via sklearn
        from sklearn.neural_network import MLPClassifier
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
        t0 = time.time()
        mlp = Pipeline([
            ("sc", StandardScaler()),
            ("mlp", MLPClassifier(hidden_layer_sizes=(128, 64, 32),
                                   activation="relu", max_iter=200,
                                   random_state=RANDOM_STATE))
        ])
        mlp.fit(X_tr, y_tr)
        t = time.time() - t0
        prob = mlp.predict_proba(X_te)[:, 1]
        pred = mlp.predict(X_te)
        return {
            "model":      mlp,
            "train_time": t,
            "metrics":    _metrics(y_te, pred, prob, "MLP (fallback)"),
        }


def _metrics(y_true, y_pred, y_prob, name: str) -> dict:
    from sklearn.metrics import (accuracy_score, precision_score,
                                  recall_score, f1_score, roc_auc_score,
                                  confusion_matrix)
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    auc  = roc_auc_score(y_true, y_prob)
    cm   = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr  = fp / (fp + tn) if (fp + tn) else 0

    print(f"\n  {name}")
    print(f"  ├─ Accuracy  : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"  ├─ Precision : {prec:.4f}")
    print(f"  ├─ Recall    : {rec:.4f}")
    print(f"  ├─ F1-score  : {f1:.4f}")
    print(f"  ├─ AUC-ROC   : {auc:.4f}")
    print(f"  ├─ FPR       : {fpr:.4f}  ({fpr*100:.2f}%)")
    print(f"  └─ Matrix    : TP={tp}  TN={tn}  FP={fp}  FN={fn}")

    return dict(accuracy=round(acc,4),  precision=round(prec,4),
                recall=round(rec,4),     f1=round(f1,4),
                auc=round(auc,4),        fpr=round(fpr,4),
                tp=int(tp), tn=int(tn), fp=int(fp), fn=int(fn),
                confusion_matrix=cm.tolist())


def _print_comparison(results: dict):
    print("\n" + "="*60)
    print("  COMPARAISON DES MODÈLES")
    print("="*60)
    header = f"{'Modèle':<18} {'Accuracy':>10} {'F1':>8} {'AUC':>8} {'FPR':>8} {'Temps(s)':>10}"
    print(header)
    print("-"*60)
    for name, r in results.items():
        m = r["metrics"]
        print(f"{name:<18} {m['accuracy']:>10.4f} {m['f1']:>8.4f} "
              f"{m['auc']:>8.4f} {m['fpr']:>8.4f} {r['train_time']:>10.2f}")
    print("="*60)

    if "RandomForest" in results:
        print("\n  Importance des features (Random Forest) :")
        fi = results["RandomForest"].get("feature_importance", {})
        for feat, imp in sorted(fi.items(), key=lambda x: -x[1]):
            bar = "█" * int(imp * 40)
            print(f"  {feat:<16} {bar:<40} {imp:.4f}")


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Entraîne les modèles ML DDoS")
    parser.add_argument("--csv",      default=None, help="Fichier CSV de données réelles")
    parser.add_argument("--n-normal", type=int, default=5000)
    parser.add_argument("--n-attack", type=int, default=5000)
    parser.add_argument("--evaluate", action="store_true",
                        help="Évaluation détaillée avec cross-validation")
    args = parser.parse_args()

    if args.csv:
        print(f"Chargement dataset : {args.csv}")
        df = pd.read_csv(args.csv)
        required = set(FEATURES + [LABEL])
        missing = required - set(df.columns)
        if missing:
            print(f"Colonnes manquantes dans le CSV : {missing}")
            print(f"Colonnes requises : {required}")
            exit(1)
    else:
        print("Génération du dataset synthétique...")
        df = generate_dataset(args.n_normal, args.n_attack)
        df.to_csv("models/dataset_uav_ddos.csv", index=False)
        print("Dataset sauvegardé → models/dataset_uav_ddos.csv")

    print(f"\nDistribution : {df[LABEL].value_counts().to_dict()}")
    results = train_all(df)
    print("\n✓ Entraînement terminé !")
    print("  → Lancer le dashboard : python dashboard_server.py")
    print("  → Lancer RYU         : ryu-manager ryu_ml_ddos.py")
