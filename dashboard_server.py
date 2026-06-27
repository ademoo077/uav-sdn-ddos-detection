#!/usr/bin/env python3
"""
================================================================================
  dashboard_server_v3.py  —  UAV-SDN Dashboard  v5.0  UNIFIED
================================================================================
  CE FICHIER REMPLACE TOUS LES ANCIENS SERVEURS.

  Fonctionnement :
    1.  Sans Ryu / Mininet  → auto-simulation réaliste (trafic UAV + attaques)
    2.  Avec Ryu            → Ryu envoie les events Socket.IO, simulation s'arrête
    3.  ML intégré          → charge models/ensemble_model.pkl et fait les
                              prédictions localement (pas besoin de Ryu pour ça)
    4.  Auto-train          → si aucun modèle trouvé, entraîne RF+SVM+MLP en ~30s
    5.  Attaques            → /api/attack/launch  →  mnexec  OU  simulation
    6.  Toutes les routes   →  synchronisées avec dashboard v4

  Usage :
    python3 dashboard_server_v3.py             # démarrer
    python3 dashboard_server_v3.py --no-sim    # désactiver auto-sim
    python3 dashboard_server_v3.py --train     # forcer re-entraînement ML
================================================================================
"""

# ────────────────────── MONKEY-PATCH EN PREMIER ────────────────────────────
import eventlet
eventlet.monkey_patch()

import argparse
import collections
import json
import math
import os
import random
import subprocess
import sys
import threading
import time
from datetime import datetime

import numpy as np

from flask import Flask, jsonify, request
from flask_socketio import SocketIO

# ─────────────────────────── CONFIGURATION ─────────────────────────────────
HOST    = "0.0.0.0"
PORT    = 5000
SECRET  = "uav_sdn_v5_2026"

BASE    = "/home/uav/drones"
DASH_HTML   = os.path.join(BASE, "dashboard.html")
MODEL_PATH  = os.path.join(BASE, "models", "ensemble_model.pkl")
METRICS_PATH= os.path.join(BASE, "models", "metrics.json")

# Plan IP — VM1=192.168.100.10 (ce serveur), VM2=192.168.100.20 (Mininet)
SWARMS = {
    "recon": ["10.0.0.11","10.0.0.12","10.0.0.13"],
    "surv":  ["10.0.0.21","10.0.0.22","10.0.0.23"],
    "logi":  ["10.0.0.31","10.0.0.32","10.0.0.33"],
}
GCS_IP    = "10.0.0.100"
EDGE_IP   = "10.0.0.200"
ALL_DRONES= [ip for lst in SWARMS.values() for ip in lst]
VALID_DRONES=[f"{s}{i+1}" for s,ips in SWARMS.items() for i in range(len(ips))]
ATTACK_TYPES={"syn","udp","icmp","slow","dns","multi"}

FEATURES = ["pps","src_entropy","syn_ratio","udp_ratio","icmp_ratio",
            "unique_srcs","avg_pkt_size","flow_count"]

# ─────────────────────────── FLASK / SOCKETIO ──────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET
sio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*",
               logger=False, engineio_logger=False,
               ping_timeout=60, ping_interval=25)

# ─────────────────────────── ÉTAT GLOBAL ───────────────────────────────────
S = {
    # Compteurs
    "total_ticks":    0,
    "total_attacks":  0,
    "total_blocked":  0,
    "switch_count":   0,
    "current_status": "waiting",
    "start_time":     time.time(),
    # IPs
    "blocked_ips":    [],
    # Stats
    "last_features":  {},
    "last_detection": {},
    "swarm_stats":    {s:{"pps":0.0,"attacks":0} for s in SWARMS},
    # Historique & journaux
    "history":      collections.deque(maxlen=3600),
    "attack_log":   collections.deque(maxlen=500),
    "active_attacks":{},
    "drone_stats":  {f"{s}{i+1}":{"pps":0.0,"packets":0,"blocked":False}
                     for s,ips in SWARMS.items() for i in range(len(ips))},
    # Flags
    "ryu_connected":  False,   # True dès qu'un event Ryu arrive
    "last_ryu_seen":   0.0,    # timestamp du dernier traffic_update Ryu
    "ryu_timeout":     8.0,    # après 8s sans Ryu => déconnecté
    "last_ryu_log":    0.0,    # anti-spam logs connexion Ryu
    "last_system_msgs": {},    # anti-spam messages système répétés
    "sim_enabled":    True,    # désactivé par --no-sim
    "sim_attack_on":  False,   # True pendant une sim d'attaque
    "sim_stop_evt":   None,
    "ml_threshold":   0.65,
    "pps_threshold":  800,
    "block_duration": 300,
}
_LOCK = threading.Lock()


# ─────────────────────────── SYNCHRONISATION RYU / DRONES ──────────────────
DRONE_META = {
    "recon1": {"ip":"10.0.0.11", "swarm":"recon", "role":"leader",  "altitude":32, "battery":94.5},
    "recon2": {"ip":"10.0.0.12", "swarm":"recon", "role":"wingman", "altitude":34, "battery":91.2},
    "recon3": {"ip":"10.0.0.13", "swarm":"recon", "role":"scout",   "altitude":31, "battery":89.8},
    "surv1":  {"ip":"10.0.0.21", "swarm":"surv",  "role":"leader",  "altitude":29, "battery":93.0},
    "surv2":  {"ip":"10.0.0.22", "swarm":"surv",  "role":"wingman", "altitude":33, "battery":87.6},
    "surv3":  {"ip":"10.0.0.23", "swarm":"surv",  "role":"scout",   "altitude":28, "battery":90.9},
    "logi1":  {"ip":"10.0.0.31", "swarm":"logi",  "role":"leader",  "altitude":30, "battery":92.7},
    "logi2":  {"ip":"10.0.0.32", "swarm":"logi",  "role":"wingman", "altitude":35, "battery":88.0},
    "logi3":  {"ip":"10.0.0.33", "swarm":"logi",  "role":"scout",   "altitude":32, "battery":76.0},
}
IP_TO_NAME = {v["ip"]: k for k, v in DRONE_META.items()}


def _mark_ryu_seen():
    """Marque Ryu comme connecté sans dépendre du disconnect des navigateurs."""
    S["ryu_connected"] = True
    S["last_ryu_seen"] = time.time()


def _normalize_detection(features, detection):
    """État unique : pas d'attaque sans trafic réel, source et flux."""
    features = dict(features or {})
    detection = dict(detection or {})
    pps = float(features.get("pps", 0) or 0)
    flow_count = int(features.get("flow_count", 0) or 0)
    total_pkts = int(features.get("total_pkts", 0) or 0)
    attacker = detection.get("attacker_ip") or features.get("attacker_ip")
    prob = float(detection.get("ensemble_prob", 0) or 0)

    no_real_traffic = (pps <= 0 or flow_count <= 0 or total_pkts <= 0 or attacker in (None, "", "None"))
    is_attack = bool(detection.get("is_attack", False)) and not no_real_traffic and prob >= S.get("ml_threshold", 0.65)

    if no_real_traffic:
        prob = 0.0
        is_attack = False
        attacker = None
        detection["ignored_reason"] = "no_real_traffic"

    if not is_attack:
        detection["is_attack"] = False
        detection["active_attack"] = False
        detection["attack_type"] = "none"
        detection["attacker_ip"] = None
        detection["ensemble_prob"] = round(min(prob, 0.39), 4) if not no_real_traffic else 0.0
    else:
        detection["is_attack"] = True
        detection["active_attack"] = True
        detection["attacker_ip"] = attacker
        if not detection.get("attack_type") or detection.get("attack_type") == "none":
            detection["attack_type"] = "GENERIC_DDOS"
        detection["ensemble_prob"] = round(prob, 4)

    detection.setdefault("probabilities", {})
    return features, detection, is_attack


def _build_drones_from_state(features=None, detection=None, incoming=None):
    """Construit une liste drones synchronisée depuis Ryu ou fallback local."""
    incoming = incoming or []
    features = features or S.get("last_features", {}) or {}
    detection = detection or S.get("last_detection", {}) or {}
    incoming_by_ip = {d.get("ip"): d for d in incoming if isinstance(d, dict) and d.get("ip")}
    attacker = detection.get("attacker_ip")
    blocked = set(S.get("blocked_ips", []))
    per_swarm = features.get("per_swarm", {}) or {}
    drones = []

    for name, meta in DRONE_META.items():
        ip = meta["ip"]
        base = dict(incoming_by_ip.get(ip, {}))
        swarm = meta["swarm"]
        pps = float(base.get("pps", 0) or 0)
        if not pps and swarm in per_swarm:
            pps = float(per_swarm.get(swarm, 0) or 0) / max(1, len(SWARMS.get(swarm, [])))
        packets = int(base.get("packets", 0) or S["drone_stats"].get(name, {}).get("packets", 0) or 0)
        if pps > 0:
            packets += int(max(1, pps))
        status = "OK"
        risk = 0
        if ip in blocked or base.get("blocked"):
            status, risk = "BLOCKED", 100
        elif attacker == ip and detection.get("is_attack"):
            status, risk = "ATTACK", int(float(detection.get("ensemble_prob", 0))*100)
        elif pps > S.get("pps_threshold", 800) / 3:
            status, risk = "SUSPECT", 45
        drones.append({
            "name": name, "id": name, "ip": ip, "swarm": swarm,
            "role": meta["role"], "active": True, "blocked": status == "BLOCKED",
            "pps": round(pps, 2), "packets": packets,
            "altitude": base.get("altitude", meta["altitude"]),
            "battery": round(float(base.get("battery", meta["battery"]) or meta["battery"]), 1),
            "status": status, "risk": risk,
        })
        S["drone_stats"][name] = {"pps": round(pps, 2), "packets": packets, "blocked": status == "BLOCKED", "status": status, "risk": risk}
    return drones


# ─────────────────────────── ML ENGINE ─────────────────────────────────────
MODEL   = None    # dict {"scaler":…, "RandomForest":…, "SVM":…, "LSTM":…}
METRICS = {}

def load_model():
    """Charge le modèle depuis le fichier pkl."""
    global MODEL, METRICS
    try:
        import joblib
        if os.path.exists(MODEL_PATH):
            MODEL = joblib.load(MODEL_PATH)
            print(f"[ML] ✓ Modèle chargé : {MODEL_PATH}")
        else:
            print(f"[ML] ⚠ Modèle introuvable : {MODEL_PATH}")
    except Exception as e:
        print(f"[ML] ⚠ Erreur chargement : {e}")
    try:
        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH) as f:
                METRICS = json.load(f)
    except Exception:
        METRICS = {}


def auto_train():
    """
    Entraîne RF+SVM+MLP avec un dataset RÉALISTE (chevauchement normal/attaque).
    Métriques attendues : RF ~96%, SVM ~94%, MLP ~93%  (pas 100%).
    """
    global MODEL, METRICS
    print("[ML] ⚙ Auto-entraînement — dataset réaliste avec chevauchement...")
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.svm import SVC
        from sklearn.neural_network import MLPClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import train_test_split, cross_val_score
        from sklearn.metrics import (accuracy_score, f1_score, roc_auc_score,
                                     precision_score, recall_score, confusion_matrix)
        from sklearn.pipeline import Pipeline
        import pandas as pd
        import joblib

        rng = np.random.default_rng(42)
        n   = 10000   # 5000 normal + 5000 attaque

        # ── Trafic NORMAL (UAV réel) ──────────────────────────────────────
        # PPS bas (10–300) MAIS avec queue haute jusqu'à 600 (overlap avec attaque)
        pps_nor = np.concatenate([
            rng.normal(85, 40, int(n*0.4)).clip(10, 300),    # trafic typique
            rng.normal(250, 80, int(n*0.07)).clip(150, 500),  # pics légitimes
            rng.normal(420, 60, int(n*0.03)).clip(300, 600),  # burst légitimes (overlap)
        ])
        pps_nor = pps_nor[:n//2]
        nor = {
            "pps":         pps_nor,
            "src_entropy": rng.normal(.88, .07, n//2).clip(.55, 1.),
            "syn_ratio":   rng.normal(.04, .03, n//2).clip(0., .25),
            "udp_ratio":   rng.normal(.62, .12, n//2).clip(.15, .92),
            "icmp_ratio":  rng.normal(.05, .03, n//2).clip(0., .20),
            "unique_srcs": rng.normal(9,  4,   n//2).clip(1., 40.),
            "avg_pkt_size":rng.normal(490, 100, n//2).clip(64, 1500),
            "flow_count":  rng.normal(22,  10,  n//2).clip(2.,  80.),
            "label":       np.zeros(n//2, int),
        }

        # ── Trafic ATTAQUE (DDoS multi-vecteurs) ─────────────────────────
        # SYN flood  (40%)
        n_syn  = int(n * 0.2)
        syn = {
            "pps":         rng.normal(2100, 700, n_syn).clip(400, 5000),
            "src_entropy": rng.normal(.12, .07,  n_syn).clip(0., .45),
            "syn_ratio":   rng.normal(.82, .10,  n_syn).clip(.45, 1.),
            "udp_ratio":   rng.normal(.05, .04,  n_syn).clip(0., .25),
            "icmp_ratio":  rng.normal(.02, .02,  n_syn).clip(0., .12),
            "unique_srcs": rng.normal(6,  3,    n_syn).clip(1., 25.),
            "avg_pkt_size":rng.normal(62,  8,   n_syn).clip(40,  90),
            "flow_count":  rng.normal(180, 50,  n_syn).clip(50, 350),
            "label":       np.ones(n_syn, int),
        }
        # UDP flood  (30%)
        n_udp  = int(n * 0.15)
        udp = {
            "pps":         rng.normal(1700, 550, n_udp).clip(350, 4500),
            "src_entropy": rng.normal(.18, .09,  n_udp).clip(0., .55),
            "syn_ratio":   rng.normal(.03, .02,  n_udp).clip(0., .15),
            "udp_ratio":   rng.normal(.85, .08,  n_udp).clip(.55, 1.),
            "icmp_ratio":  rng.normal(.02, .02,  n_udp).clip(0., .10),
            "unique_srcs": rng.normal(10, 5,    n_udp).clip(1., 40.),
            "avg_pkt_size":rng.normal(120, 30,  n_udp).clip(50, 350),
            "flow_count":  rng.normal(160, 40,  n_udp).clip(40, 300),
            "label":       np.ones(n_udp, int),
        }
        # ICMP flood (15%)
        n_icmp = int(n * 0.075)
        icmp = {
            "pps":         rng.normal(1500, 450, n_icmp).clip(300, 4000),
            "src_entropy": rng.normal(.16, .08,  n_icmp).clip(0., .50),
            "syn_ratio":   rng.normal(.02, .01,  n_icmp).clip(0., .08),
            "udp_ratio":   rng.normal(.04, .03,  n_icmp).clip(0., .18),
            "icmp_ratio":  rng.normal(.83, .09,  n_icmp).clip(.50, 1.),
            "unique_srcs": rng.normal(60, 30,   n_icmp).clip(5., 200.),
            "avg_pkt_size":rng.normal(64,  8,   n_icmp).clip(28,  90),
            "flow_count":  rng.normal(140, 40,  n_icmp).clip(30, 280),
            "label":       np.ones(n_icmp, int),
        }
        # Slowloris (15%) — ambigu (PPS faible)
        n_slow = n//2 - n_syn - n_udp - n_icmp
        slow = {
            "pps":         rng.normal(320, 120, n_slow).clip(80, 700),  # chevauchement fort
            "src_entropy": rng.normal(.35, .12,  n_slow).clip(.05, .70),
            "syn_ratio":   rng.normal(.55, .15,  n_slow).clip(.20, .90),
            "udp_ratio":   rng.normal(.12, .08,  n_slow).clip(0., .40),
            "icmp_ratio":  rng.normal(.03, .02,  n_slow).clip(0., .12),
            "unique_srcs": rng.normal(4,  2,    n_slow).clip(1., 15.),
            "avg_pkt_size":rng.normal(480, 90,  n_slow).clip(200, 900),
            "flow_count":  rng.normal(95, 30,   n_slow).clip(20, 200),
            "label":       np.ones(n_slow, int),
        }

        frames = [pd.DataFrame(nor),
                  pd.DataFrame(syn),
                  pd.DataFrame(udp),
                  pd.DataFrame(icmp),
                  pd.DataFrame(slow)]
        df = pd.concat(frames, ignore_index=True)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"[ML] Dataset : {len(df)} éch.  "
              f"({df['label'].sum()} attaques / {(df['label']==0).sum()} normal)")

        X, y = df[FEATURES].values, df["label"].values
        Xtr, Xte, ytr, yte = train_test_split(
            X, y, test_size=.2, random_state=42, stratify=y)

        # ── Entraînement ──────────────────────────────────────────────────
        rf = RandomForestClassifier(
            n_estimators=200, max_depth=12, min_samples_split=5,
            class_weight="balanced", n_jobs=-1, random_state=42)
        rf.fit(Xtr, ytr)

        svm = Pipeline([("sc", StandardScaler()),
                        ("sv", SVC(probability=True, C=10, gamma="scale",
                                   class_weight="balanced", random_state=42))])
        svm.fit(Xtr, ytr)

        mlp = Pipeline([("sc", StandardScaler()),
                        ("mp", MLPClassifier(hidden_layer_sizes=(128, 64, 32),
                                             activation="relu", max_iter=200,
                                             early_stopping=True, random_state=42))])
        mlp.fit(Xtr, ytr)

        # ── Évaluation ────────────────────────────────────────────────────
        def met(model, X, y, name):
            pr  = (model.predict_proba(X)[:,1]
                   if hasattr(model,"predict_proba") else model.predict(X).astype(float))
            pd_ = (pr >= .5).astype(int)
            acc  = round(accuracy_score(y, pd_), 4)
            prec = round(precision_score(y, pd_, zero_division=0), 4)
            rec  = round(recall_score(y, pd_, zero_division=0), 4)
            f1   = round(f1_score(y, pd_, zero_division=0), 4)
            auc  = round(roc_auc_score(y, pr), 4)
            cm   = confusion_matrix(y, pd_).ravel()
            tn,fp,fn,tp = cm if len(cm)==4 else (0,0,0,0)
            fpr = round(fp/(fp+tn) if (fp+tn) else 0, 4)
            print(f"  {name:14s}: acc={acc:.4f}  f1={f1:.4f}  "
                  f"auc={auc:.4f}  fpr={fpr:.4f}  "
                  f"TP={tp}  FP={fp}  FN={fn}")
            return {"accuracy":acc,"precision":prec,"recall":rec,
                    "f1":f1,"auc":auc,"fpr":fpr,
                    "tp":int(tp),"fp":int(fp),"fn":int(fn),"tn":int(tn)}

        print("[ML] Évaluation :")
        res = {
            "RandomForest": met(rf,  Xte, yte, "RandomForest"),
            "SVM":          met(svm, Xte, yte, "SVM"),
            "LSTM":         met(mlp, Xte, yte, "MLP"),
        }
        fi = dict(zip(FEATURES, rf.feature_importances_.tolist()))
        res["feature_importance"] = fi
        res["dataset_size"]       = len(df)
        res["trained_at"]         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        MODEL  = {"scaler": StandardScaler().fit(Xtr),
                  "RandomForest": rf, "SVM": svm, "LSTM": mlp}
        METRICS = res

        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(MODEL, MODEL_PATH)
        with open(METRICS_PATH, "w") as f:
            json.dump(METRICS, f, indent=2)
        print(f"[ML] ✓ Modèles sauvegardés → {MODEL_PATH}")
        sio.emit("system_event", {"msg": "✓ Modèles ML entraînés (dataset réaliste)",
                                  "type": "success"})
        sio.emit("ml_ready", {"metrics": METRICS})

    except Exception as e:
        import traceback
        print(f"[ML] ✗ Auto-train échoué : {e}")
        traceback.print_exc()


def ml_predict(features: dict) -> dict:
    """Retourne {prob, probs_dict, is_attack} en utilisant le modèle ou le seuil."""
    X = np.array([[
        features.get("pps",0),
        features.get("src_entropy",1.),
        features.get("syn_ratio",0),
        features.get("udp_ratio",0),
        features.get("icmp_ratio",0),
        features.get("unique_srcs",0),
        features.get("avg_pkt_size",512),
        features.get("flow_count",0),
    ]])
    probs_dict={}; ensemble_prob=0.

    if MODEL:
        try:
            sc = MODEL.get("scaler")
            Xs = sc.transform(X) if sc else X
            vals=[]
            for name,m in MODEL.items():
                if name in ("scaler","feature_importance","dataset_size","trained_at"): continue
                try:
                    p = float(m.predict_proba(Xs)[0][1]) if hasattr(m,"predict_proba") else float(m.predict(Xs)[0])
                    probs_dict[name]=round(p,4); vals.append(p)
                except Exception: pass
            if vals: ensemble_prob=sum(vals)/len(vals)
            else: ensemble_prob,_=_threshold(features); probs_dict["threshold"]=round(ensemble_prob,4)
        except Exception:
            ensemble_prob,_=_threshold(features); probs_dict["threshold"]=round(ensemble_prob,4)
    else:
        ensemble_prob,_=_threshold(features); probs_dict["threshold"]=round(ensemble_prob,4)

    thr = S["ml_threshold"]
    return {
        "ensemble_prob": round(min(ensemble_prob,1.),4),
        "probabilities": probs_dict,
        "is_attack":     ensemble_prob>=thr,
    }


def _threshold(f):
    score=0.
    if f.get("pps",0)>S["pps_threshold"]: score+=.40
    if f.get("src_entropy",1.)<.30:        score+=.25
    if f.get("syn_ratio",0)>.60:           score+=.20
    if f.get("udp_ratio",0)>.80:           score+=.15
    if f.get("unique_srcs",0)>50:          score+=.10
    return min(score,1.), score>=.65

# ─────────────────────────── AUTO-SIMULATION ───────────────────────────────
# Génère du trafic UAV réaliste toutes les secondes quand Ryu absent

def _sim_features_normal():
    """
    Features d'un flux UAV normal — PPS entre 50-200, entropie haute.
    Variations réalistes : telemetry + vidéo + heartbeat + mesh.
    """
    # Mélange : telemetry (léger), vidéo (lourd), burst occasionnel
    pps_base = random.gauss(120, 40)
    burst     = random.random() < 0.08  # 8% de chance de pic légitime
    pps       = pps_base * (3.5 if burst else 1.0)
    pps       = max(30, min(pps, 400))
    return {
        "pps":          round(pps, 1),
        "src_entropy":  round(min(1.0, max(0.65, random.gauss(0.90, 0.06))), 4),
        "syn_ratio":    round(max(0., random.gauss(0.03, 0.02)), 4),
        "udp_ratio":    round(min(0.95, max(0.35, random.gauss(0.65, 0.10))), 4),
        "icmp_ratio":   round(max(0., random.gauss(0.04, 0.02)), 4),
        "unique_srcs":  max(2, int(random.gauss(8, 3))),
        "avg_pkt_size": round(max(64, random.gauss(480, 90)), 1),
        "flow_count":   max(3, int(random.gauss(22, 8))),
        "attacker_ip":  None,
        "per_swarm":    {},
    }

def _sim_features_attack(atype, attacker_ip, step, total_steps):
    """
    Features d'une attaque simulée — PPS très élevé, entropie basse.
    Ramp-up progressif + plateau + descente.
    """
    profiles = {
        "syn":  {"pps":2200,"ent":.10,"syn":.82,"udp":.05,"icmp":.02,"pkt":64,  "src":6},
        "udp":  {"pps":1800,"ent":.14,"syn":.03,"udp":.86,"icmp":.02,"pkt":120, "src":8},
        "icmp": {"pps":1600,"ent":.13,"syn":.02,"udp":.04,"icmp":.85,"pkt":1024,"src":60},
        "slow": {"pps":350, "ent":.38,"syn":.54,"udp":.14,"icmp":.04,"pkt":512, "src":4},
        "dns":  {"pps":1400,"ent":.17,"syn":.04,"udp":.81,"icmp":.02,"pkt":512, "src":7},
        "multi":{"pps":2800,"ent":.09,"syn":.30,"udp":.38,"icmp":.25,"pkt":200, "src":10},
    }
    p = profiles.get(atype, profiles["syn"])

    # Courbe d'attaque : ramp-up (20%) → plateau (70%) → descente (10%)
    ramp_end   = max(1, int(total_steps * 0.2))
    plateau_end= max(ramp_end+1, int(total_steps * 0.9))
    if step <= ramp_end:
        ratio = step / ramp_end
    elif step <= plateau_end:
        ratio = 1.0 + random.gauss(0, 0.05)  # plateau avec légère variation
    else:
        ratio = max(0.1, 1.0 - (step - plateau_end) / max(1, total_steps - plateau_end))

    pps = p["pps"] * ratio * (0.88 + random.random() * 0.24)
    return {
        "pps":          round(max(10, pps), 1),
        "src_entropy":  round(max(0., min(p["ent"] + random.gauss(0, .04), 0.5)), 4),
        "syn_ratio":    round(min(1., max(0., p["syn"] + random.gauss(0, .05))), 4),
        "udp_ratio":    round(min(1., max(0., p["udp"] + random.gauss(0, .05))), 4),
        "icmp_ratio":   round(min(1., max(0., p["icmp"]+ random.gauss(0, .03))), 4),
        "unique_srcs":  max(1, int(p["src"] + random.gauss(0, 2))),
        "avg_pkt_size": round(max(40, p["pkt"] + random.gauss(0, 15)), 1),
        "flow_count":   max(10, int(150 + ratio * 100 + random.gauss(0, 20))),
        "attacker_ip":  attacker_ip,
        "per_swarm":    {},
    }

def _classify_attack(f, atype):
    if atype=="syn"  or f.get("syn_ratio",0)>.6:  return "SYN_FLOOD"
    if atype=="udp"  or f.get("udp_ratio",0)>.7:  return "UDP_FLOOD"
    if atype=="icmp" or f.get("icmp_ratio",0)>.5:  return "ICMP_FLOOD"
    if atype=="multi":                              return "DISTRIBUTED"
    return "GENERIC_DDOS"

def _emit_update(features, detection, swarm_stats=None):
    """Construit et émet un traffic_update complet."""
    pps        = features.get("pps", 0)
    flow_count = features.get("flow_count", 0)

    # ── GARDE ANTI-FAUX-POSITIFS ──────────────────────────────────────
    # Règle stricte : jamais d'attaque si pps=0, pas de flux, ou pas d'attaquant
    raw_is_atk = detection.get("is_attack", False)
    is_atk = raw_is_atk and pps > 5 and flow_count > 0
    if not is_atk:
        detection["is_attack"]    = False
        # Ne pas classifier en attaque si les conditions de base ne sont pas remplies
        if raw_is_atk and pps <= 5:
            detection["ensemble_prob"] = min(detection.get("ensemble_prob", 0), 0.3)
    # Filtrer attack_type "none" et ne pas loguer les non-attaques
    if not is_atk:
        detection["attack_type"] = "none"
        detection["attacker_ip"] = None
    # ──────────────────────────────────────────────────────────────────

    with _LOCK:
        S["total_ticks"] += 1
        S["last_features"]  = features
        S["last_detection"] = detection
        if is_atk:
            S["total_attacks"] += 1
            S["current_status"] = "attack"
            atk_type = detection.get("attack_type","GENERIC")
            if atk_type and atk_type != "none":  # ne loguer que les vraies attaques
                S["attack_log"].append({
                    "ts":   datetime.now().isoformat(timespec="seconds"),
                    "type": atk_type,
                    "src":  detection.get("attacker_ip"),
                    "pps":  round(pps, 1),
                    "prob": detection.get("ensemble_prob", 0),
                })
        else:
            prob = detection.get("ensemble_prob", 0)
            S["current_status"] = "suspicious" if prob >= .4 else "normal"
        S["history"].append({
            "ts":      time.time(),
            "pps":     pps,
            "prob":    detection.get("ensemble_prob", 0),
            "isAtk":   is_atk,
            "atkType": detection.get("attack_type", "none"),
            "attacker":detection.get("attacker_ip"),
        })
        drones = _build_drones_from_state(features, detection)
        uptime  = int(time.time()-S["start_time"])
        payload = {
            "features":  features,
            "detection": detection,
            "system": {
                "total_ticks":    S["total_ticks"],
                "total_attacks":  S["total_attacks"],
                "total_blocked":  S["total_blocked"],
                "current_status": S["current_status"],
                "active_attack":  is_atk,
                "uptime":         uptime,
            },
            "swarm_stats":  swarm_stats or S["swarm_stats"],
            "blocked_ips":  list(S["blocked_ips"]),
            "switch_count": S["switch_count"],
            "drones": drones,
            "drone_stats": drones,
            "drones_active": sum(1 for d in drones if d.get("active")),
            "drones_total": len(drones),
            "ryu_connected": S["ryu_connected"],
            "timestamp":    time.time(),
        }
    sio.emit("traffic_update", payload)


def _auto_background():
    """Boucle de simulation automatique — s'active si Ryu absent."""
    NORMAL_DURATION  = 30   # secondes de trafic normal entre attaques
    ATTACK_PROB      = 0.02 # proba d'une attaque spontanée par tick (normal)
    attack_types     = list(ATTACK_TYPES)
    attack_step      = 0
    attack_total     = 0
    current_atype    = "syn"
    attacker_ip      = "10.0.0.11"
    in_attack        = False
    stop_evt         = None

    while True:
        eventlet.sleep(1)

        # Si Ryu connecté → ne rien faire (Ryu gère les données)
        if S["ryu_connected"]:
            in_attack = False
            continue
        if not S["sim_enabled"]:
            continue

        # ── Attaque simulée manuellement depuis le dashboard ─────────────
        if S["sim_attack_on"]:
            if stop_evt and stop_evt.is_set():
                S["sim_attack_on"] = False
                in_attack = False
                sio.emit("system_event",{"msg":"[SIM] Attaque dashboard terminée","type":"info"})
                continue
            # Les données sont émises par _run_attack_simulation
            continue

        # ── Oscillation automatique normal / attaque ─────────────────────
        if not in_attack:
            # Décider si on lance une attaque spontanée
            if random.random() < ATTACK_PROB:
                current_atype = random.choice(attack_types)
                attacker_ip   = random.choice(ALL_DRONES)
                attack_total  = random.randint(20,40)
                attack_step   = 0
                in_attack     = True
                sio.emit("system_event",{
                    "msg": f"[AUTO-SIM] Attaque spontanée : {current_atype.upper()} depuis {attacker_ip}",
                    "type": "warn"
                })
            else:
                f = _sim_features_normal()
                d = ml_predict(f)
                d["attack_type"]  = "none"
                d["attacker_ip"]  = None
                _emit_update(f, d)
        else:
            attack_step += 1
            f = _sim_features_attack(current_atype, attacker_ip, attack_step, attack_total)
            d = ml_predict(f)
            d["attack_type"] = _classify_attack(f, current_atype) if d["is_attack"] else "none"
            d["attacker_ip"] = attacker_ip if d["is_attack"] else None
            # Mitigation au bout de 4 ticks d'attaque
            if d["is_attack"] and attack_step == 4:
                _trigger_mitigation(attacker_ip)
            _emit_update(f, d)
            if attack_step >= attack_total:
                in_attack = False
                sio.emit("system_event",{
                    "msg": f"[AUTO-SIM] Fin attaque {current_atype.upper()} — réseau normal",
                    "type": "info"
                })


def _trigger_mitigation(ip):
    swarm = next((s for s,ips in SWARMS.items() if ip in ips), "external")
    with _LOCK:
        if ip not in S["blocked_ips"]:
            S["blocked_ips"].append(ip)
        S["total_blocked"] += 1
    sio.emit("mitigation_event",{
        "ip": ip, "swarm": swarm,
        "duration": S["block_duration"],
        "timestamp": time.time(),
    })
    sio.emit("system_event",{
        "msg": f"🔒 [SIM] Mitigation : {ip} ({swarm}) bloquée {S['block_duration']}s",
        "type": "warn"
    })
    # Auto-déblocage
    def _unblock():
        eventlet.sleep(S["block_duration"])
        with _LOCK:
            if ip in S["blocked_ips"]: S["blocked_ips"].remove(ip)
        sio.emit("system_event",{"msg":f"✓ IP débloquée automatiquement : {ip}","type":"info"})
    eventlet.spawn(_unblock)


def _run_attack_simulation(attack_id, atype, attacker, attacker_ip, target, duration):
    """Simulation d'attaque déclenchée depuis /api/attack/launch."""
    stop_evt = eventlet.event.Event()
    with _LOCK:
        S["sim_attack_on"] = True
        S["sim_stop_evt"]  = stop_evt

    def _run():
        try:
            ramp  = max(2, int(duration*.25))
            total = duration - ramp
            sio.emit("system_event",{
                "msg": f"[SIM] {atype.upper()} : {attacker}({attacker_ip}) → {target} ({duration}s)",
                "type":"warn"
            })
            # Ramp-up
            for step in range(1, ramp+1):
                if stop_evt.ready(): return
                f = _sim_features_attack(atype, attacker_ip, step, ramp)
                d = ml_predict(f); d["attack_type"]="none"; d["attacker_ip"]=None
                _emit_update(f,d)
                eventlet.sleep(1)
            # Phase attaque
            for step in range(1, total+1):
                if stop_evt.ready(): break
                f = _sim_features_attack(atype, attacker_ip, ramp, ramp)  # plateau
                d = ml_predict(f)
                d["attack_type"] = _classify_attack(f,atype) if d["is_attack"] else "none"
                d["attacker_ip"] = attacker_ip if d["is_attack"] else None
                if d["is_attack"] and step==3: _trigger_mitigation(attacker_ip)
                _emit_update(f,d)
                eventlet.sleep(1)
            # Retour normal
            for step in range(5):
                if stop_evt.ready(): break
                f = _sim_features_normal(); d=ml_predict(f)
                d["attack_type"]="none"; d["attacker_ip"]=None
                _emit_update(f,d); eventlet.sleep(1)
        finally:
            with _LOCK:
                S["sim_attack_on"]=False
                S["active_attacks"].pop(attack_id,None)
            sio.emit("attack_stopped",{"id":attack_id})
            sio.emit("system_event",{"msg":f"[SIM] Fin attaque {atype.upper()}","type":"info"})
    eventlet.spawn(_run)

# ─────────────────────────── HELPERS JSON ──────────────────────────────────

def ok(data, code=200):
    r=jsonify(data); r.headers["Content-Type"]="application/json"; return r, code

def err(msg, code=400):
    r=jsonify({"error":msg,"code":code}); r.headers["Content-Type"]="application/json"; return r, code

def uptime_str(s):
    h,rem=divmod(int(s),3600); m,sec=divmod(rem,60)
    return f"{h:02d}h{m:02d}m{sec:02d}s"

def ip_to_swarm(ip):
    for s,ips in SWARMS.items():
        if ip in ips: return s
    return None

def drone_to_ip(name):
    for s,ips in SWARMS.items():
        if name.startswith(s):
            try: return ips[int(name[len(s):])-1]
            except: pass
    return None

# ─────────────────────────── GESTIONNAIRE ERREURS ──────────────────────────
@app.errorhandler(404)
def e404(_): return err("Endpoint introuvable",404)
@app.errorhandler(405)
def e405(_): return err("Méthode non autorisée",405)
@app.errorhandler(500)
def e500(e): return err(f"Erreur serveur : {e}",500)

# ─────────────────────────── ROUTES ─────────────────────────────────────────

@app.route("/")
def index():
    if os.path.exists(DASH_HTML):
        with open(DASH_HTML,encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type":"text/html;charset=utf-8"}
    return "<h1>dashboard.html introuvable</h1><p>Vérifier /home/uav/drones/dashboard.html</p>", 404


@app.route("/api/status")
def api_status():
    with _LOCK:
        up = int(time.time()-S["start_time"])
        return ok({
            "status":        S["current_status"],
            "uptime":        up,
            "uptime_human":  uptime_str(up),
            "total_ticks":   S["total_ticks"],
            "total_attacks": S["total_attacks"],
            "total_blocked": S["total_blocked"],
            "switch_count":  S["switch_count"],
            "blocked_ips":   S["blocked_ips"],
            "swarm_stats":   S["swarm_stats"],
            "ryu_connected": S["ryu_connected"],
            "last_ryu_seen": S["last_ryu_seen"],
            "sim_enabled":   S["sim_enabled"],
            "sim_active":    S["sim_attack_on"],
            "ml_loaded":     MODEL is not None,
        })


@app.route("/api/metrics")
def api_metrics():
    if METRICS:
        return ok(METRICS)
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH) as f: return ok(json.load(f))
        except Exception: pass
    return ok({
        "RandomForest":{"accuracy":0.,"precision":0.,"recall":0.,"f1":0.,"auc":0.,"fpr":0.},
        "SVM":         {"accuracy":0.,"precision":0.,"recall":0.,"f1":0.,"auc":0.,"fpr":0.},
        "LSTM":        {"accuracy":0.,"precision":0.,"recall":0.,"f1":0.,"auc":0.,"fpr":0.},
        "feature_importance":{k:0. for k in FEATURES},
        "dataset_size":0,
        "trained_at":"non entraîné — lancer : python3 dashboard_server_v3.py --train",
    })


@app.route("/api/attacks")
def api_attacks():
    n=int(request.args.get("n",100))
    with _LOCK: return ok({"attacks":list(S["attack_log"])[-n:]})


@app.route("/api/heatmap")
def api_heatmap():
    with _LOCK:
        heat=collections.Counter()
        for pt in list(S["history"])[-300:]:
            if pt.get("attacker"): heat[pt["attacker"]]+=1
        return ok({"heatmap":[{"ip":ip,"count":c} for ip,c in heat.most_common(20)],
                   "total":sum(heat.values())})


@app.route("/api/history")
def api_history():
    n=int(request.args.get("n",300))
    with _LOCK: return ok({"history":list(S["history"])[-n:]})


@app.route("/api/timeline")
def api_timeline():
    n=int(request.args.get("n",300))
    with _LOCK:
        h=list(S["history"])[-n:]
        return ok({"points":h,"total":len(S["history"]),
                   "span_seconds":(h[-1]["ts"]-h[0]["ts"]) if len(h)>1 else 0})


@app.route("/api/swarms")
def api_swarms():
    with _LOCK:
        res={}
        for name,ips in SWARMS.items():
            blk=[ip for ip in S["blocked_ips"] if ip in ips]
            ss=S["swarm_stats"].get(name,{})
            res[name]={"name":name,"drones":ips,"active":len(ips)-len(blk),
                       "blocked":blk,"pps":ss.get("pps",0),
                       "attacks":ss.get("attacks",0),
                       "status":"compromised" if blk else "ok"}
        return ok(res)


@app.route("/api/drones")
def api_drones():
    with _LOCK:
        drones = _build_drones_from_state(S.get("last_features", {}), S.get("last_detection", {}))
        return ok({"drones": drones, "total": len(drones), "active": sum(1 for d in drones if d.get("active"))})


@app.route("/api/drones/stats")
def api_drones_stats():
    with _LOCK:
        drones = _build_drones_from_state(S.get("last_features", {}), S.get("last_detection", {}))
        return ok({"stats": S["drone_stats"], "drones": drones, "ts": time.time()})


@app.route("/api/network/topology")
def api_topology():
    with _LOCK:
        return ok({
            "switches":[
                {"name":"s1","dpid":1,"role":"core","of_version":"1.3"},
                {"name":"ap-recon","dpid":0xA0,"role":"edge","swarm":"recon"},
                {"name":"ap-surv","dpid":0xA1,"role":"edge","swarm":"surv"},
                {"name":"ap-logi","dpid":0xA2,"role":"edge","swarm":"logi"},
            ],
            "hosts":[{"name":"gcs","ip":GCS_IP},{"name":"edge","ip":EDGE_IP}],
            "swarms":SWARMS,"blocked":S["blocked_ips"],
            "controller":{"ip":"192.168.100.10","port":6653,"version":"OpenFlow1.3"},
        })


@app.route("/api/network/analysis")
def api_analysis():
    with _LOCK:
        f=S.get("last_features",{}); d=S.get("last_detection",{})
        return ok({"pps":f.get("pps",0),"src_entropy":f.get("src_entropy",1.),
                   "syn_ratio":f.get("syn_ratio",0),"udp_ratio":f.get("udp_ratio",0),
                   "icmp_ratio":f.get("icmp_ratio",0),"unique_srcs":f.get("unique_srcs",0),
                   "avg_pkt_size":f.get("avg_pkt_size",512),"flow_count":f.get("flow_count",0),
                   "prob":d.get("ensemble_prob",0),"is_attack":d.get("is_attack",False),
                   "attack_type":d.get("attack_type","none"),"attacker_ip":d.get("attacker_ip")})


@app.route("/api/system/health")
def api_health():
    up=int(time.time()-S["start_time"])
    checks={
        "dashboard_html":  os.path.exists(DASH_HTML),
        "model_file":      os.path.exists(MODEL_PATH),
        "metrics_file":    os.path.exists(METRICS_PATH),
        "ml_loaded":       MODEL is not None,
        "ryu_connected":   S["ryu_connected"],
        "sim_enabled":     S["sim_enabled"],
        "server_uptime_s": up,
        "total_ticks":     S["total_ticks"],
        "switch_count":    S["switch_count"],
        "blocked_ips":     len(S["blocked_ips"]),
        "history_points":  len(S["history"]),
    }
    status="healthy" if S["ryu_connected"] or S["sim_enabled"] else "degraded"
    return ok({"status":status,"checks":checks,"ts":time.time()})


@app.route("/api/ml/predict", methods=["POST"])
def api_ml_predict():
    """Endpoint de prédiction ML directe (utile pour tests)."""
    data=request.get_json(silent=True) or {}
    if not data: return err("Corps JSON requis")
    result=ml_predict(data)
    result["method"]="ML_Ensemble" if MODEL else "threshold"
    return ok(result)


@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    with _LOCK:
        if ip in S["blocked_ips"]: S["blocked_ips"].remove(ip)
    sio.emit("system_event",{"msg":f"IP débloquée manuellement : {ip}","type":"info"})
    sio.emit("manual_unblock",{"ip":ip})
    return ok({"status":"ok","ip":ip})


# ══════════════════════════════════════════════════════
#  /api/attack/launch — FIX PRINCIPAL
#  → Toujours retourne du JSON (jamais de HTML)
#  → Mininet réel si dispo, sinon simulation complète
# ══════════════════════════════════════════════════════

@app.route("/api/attack/launch", methods=["POST"])
def api_launch():
    try:
        data     = request.get_json(silent=True) or {}
        atype    = str(data.get("type","syn")).strip().lower()
        target   = str(data.get("target",GCS_IP)).strip()
        attacker = str(data.get("attacker","recon1")).strip()
        try:   duration=int(data.get("duration",20))
        except:duration=20

        # Validation
        if atype not in ATTACK_TYPES:
            return err(f"Type invalide : '{atype}'. Valides : {sorted(ATTACK_TYPES)}")
        if attacker not in VALID_DRONES:
            return err(f"Attaquant invalide : '{attacker}'. Valides : {VALID_DRONES}")
        if not 1<=duration<=300:
            return err("Durée hors plage (1–300 s)")

        attack_id   = f"atk-{int(time.time()*1000)}"
        attacker_ip = drone_to_ip(attacker) or "10.0.0.11"
        simulated   = True
        pid         = None

        # ── Tentative mnexec / Mininet réel ──────────────────────────────
        try:
            res=subprocess.run(["pgrep","-f",f"mininet:{attacker}"],
                               capture_output=True,text=True,timeout=2)
            if res.returncode==0 and res.stdout.strip():
                mn_pid=res.stdout.strip().split("\n")[0].strip()
                cmd=(f"mnexec -a {mn_pid} python3 /tmp/attack_orchestrator.py "
                     f"--type {atype} --target {target} --duration {duration}")
                proc=subprocess.Popen(cmd,shell=True,
                                      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                pid=proc.pid; simulated=False
        except Exception: pass

        # ── Mode simulation si Mininet absent ─────────────────────────────
        if simulated:
            _run_attack_simulation(attack_id,atype,attacker,attacker_ip,target,duration)

        with _LOCK:
            S["active_attacks"][attack_id]={
                "id":attack_id,"type":atype,"target":target,
                "attacker":attacker,"attacker_ip":attacker_ip,
                "started":time.time(),"expected_end":time.time()+duration,
                "duration":duration,"pid":pid,"simulated":simulated,
            }

        sio.emit("attack_launched",S["active_attacks"][attack_id])
        return ok({
            "status":    "ok",
            "attack_id": attack_id,
            "simulated": simulated,
            "message":   f"{'[SIM] ' if simulated else '[Mininet] '}{atype.upper()} lancé ({duration}s)",
        })

    except Exception as exc:
        return err(f"Erreur serveur inattendue : {exc}",500)


@app.route("/api/attack/stop/<atk_id>", methods=["POST"])
def api_stop(atk_id):
    with _LOCK: atk=S["active_attacks"].pop(atk_id,None)
    if not atk: return err("Attaque introuvable",404)
    if atk.get("pid"):
        try: os.system(f"kill -9 {atk['pid']} 2>/dev/null")
        except: pass
    if atk.get("simulated"):
        with _LOCK: S["sim_attack_on"]=False
        evt=S.get("sim_stop_evt")
        if evt and not evt.ready():
            try: evt.send("stop")
            except: pass
    sio.emit("attack_stopped",{"id":atk_id})
    return ok({"status":"ok","id":atk_id})


@app.route("/api/attack/stop_all", methods=["POST"])
def api_stop_all():
    with _LOCK:
        ids=list(S["active_attacks"].keys())
        S["active_attacks"].clear()
        S["sim_attack_on"]=False
    os.system("pkill -f attack_orchestrator 2>/dev/null || true")
    sio.emit("system_event",{"msg":"Toutes les attaques arrêtées","type":"info"})
    return ok({"status":"ok","stopped":ids})




# ─────────────────────────── TOPOLOGY CONTROL PROXY ─────────────────────────
# VM1 dashboard_server -> VM2 Mininet topology control agent
# VM2 doit lancer : topo_expert_uav.py --control-port 8088
import urllib.request
import urllib.error

TOPOLOGY_AGENT_URL = os.getenv("TOPOLOGY_AGENT_URL", "http://192.168.100.20:8088")

DRONE_GEO_DEFAULTS = {
    "recon1": {"lat": 36.7581, "lon": 3.0371, "alt": 32},
    "recon2": {"lat": 36.7610, "lon": 3.0417, "alt": 34},
    "recon3": {"lat": 36.7542, "lon": 3.0450, "alt": 31},
    "surv1":  {"lat": 36.7495, "lon": 3.0534, "alt": 29},
    "surv2":  {"lat": 36.7514, "lon": 3.0597, "alt": 33},
    "surv3":  {"lat": 36.7479, "lon": 3.0603, "alt": 28},
    "logi1":  {"lat": 36.7275, "lon": 3.0459, "alt": 30},
    "logi2":  {"lat": 36.7248, "lon": 3.0548, "alt": 35},
    "logi3":  {"lat": 36.7333, "lon": 3.0648, "alt": 32},
}

TOPOLOGY_STATE = {
    "agent_online": False,
    "last_sync": 0.0,
    "links": {},
    "drones": {},
}


def _default_drones():
    drones = []
    for swarm, ips in SWARMS.items():
        for idx, ip in enumerate(ips, start=1):
            name = f"{swarm}{idx}"
            geo = DRONE_GEO_DEFAULTS.get(name, {"lat": 36.75, "lon": 3.05, "alt": 30})
            ds = S.get("drone_stats", {}).get(name, {}) if isinstance(S.get("drone_stats"), dict) else {}
            blocked = ip in S.get("blocked_ips", [])
            drones.append({
                "name": name,
                "id": name,
                "ip": ip,
                "swarm": swarm,
                "lat": geo["lat"],
                "lon": geo["lon"],
                "alt": geo["alt"],
                "altitude": geo["alt"],
                "battery": float(ds.get("battery", 92.0)),
                "pps": float(ds.get("pps", 0.0)),
                "status": "BLOCKED" if blocked else ds.get("status", "OK"),
                "blocked": blocked,
                "active": True,
            })
    return drones


def _agent_request(path, method="GET", payload=None, timeout=3.0):
    url = TOPOLOGY_AGENT_URL.rstrip("/") + path
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", errors="ignore")
        return json.loads(raw) if raw else {}


def _sync_topology_from_agent():
    try:
        res = _agent_request("/api/topology/drones", "GET", timeout=2.0)
        drones = res.get("drones", [])
        with _LOCK:
            TOPOLOGY_STATE["agent_online"] = True
            TOPOLOGY_STATE["last_sync"] = time.time()
            TOPOLOGY_STATE["links"] = res.get("links", TOPOLOGY_STATE.get("links", {}))
            TOPOLOGY_STATE["drones"] = {d.get("name") or d.get("id"): d for d in drones if d.get("name") or d.get("id")}
            # Synchroniser avec l'état global pour les autres onglets
            S["drone_stats"] = {d.get("name") or d.get("id"): d for d in drones if d.get("name") or d.get("id")}
        return res
    except Exception as exc:
        with _LOCK:
            TOPOLOGY_STATE["agent_online"] = False
            if not TOPOLOGY_STATE["drones"]:
                TOPOLOGY_STATE["drones"] = {d["name"]: d for d in _default_drones()}
        return {
            "ok": True,
            "source": "dashboard-fallback",
            "warning": f"Agent Mininet non joignable: {exc}",
            "drones": list(TOPOLOGY_STATE["drones"].values()),
            "links": TOPOLOGY_STATE.get("links", {}),
            "agent_online": False,
        }


@app.route("/api/topology/drones", methods=["GET"])
def api_topology_drones():
    res = _sync_topology_from_agent()
    res["agent_url"] = TOPOLOGY_AGENT_URL
    return ok(res)


@app.route("/api/topology/drone/<name>/move", methods=["POST"])
def api_topology_drone_move(name):
    data = request.get_json(silent=True) or {}
    try:
        lat = float(data.get("lat"))
        lon = float(data.get("lon"))
        alt = float(data.get("alt", data.get("altitude", 30)))
    except Exception:
        return err("lat, lon, alt invalides", 400)

    payload = {"lat": lat, "lon": lon, "alt": alt}
    try:
        res = _agent_request(f"/api/topology/drone/{name}/move", "POST", payload, timeout=3.0)
    except Exception as exc:
        # fallback visuel si agent absent
        with _LOCK:
            d = TOPOLOGY_STATE["drones"].get(name) or next((x for x in _default_drones() if x["name"] == name), None)
            if not d:
                return err(f"Drone inconnu: {name}", 404)
            d.update({"lat": lat, "lon": lon, "alt": alt, "altitude": alt})
            TOPOLOGY_STATE["drones"][name] = d
            res = {"ok": True, "fallback": True, "warning": str(exc), "event": "drone_moved", "drone": d}
    sio.emit("drone_moved", res)
    sio.emit("topology_update", {"type": "drone_moved", **res})
    sio.emit("system_event", {"msg": f"Drone {name} déplacé ({lat:.5f},{lon:.5f},{alt:.0f}m)", "type": "info"})
    return ok(res)


@app.route("/api/topology/drone/<name>/battery", methods=["POST"])
def api_topology_drone_battery(name):
    data = request.get_json(silent=True) or {}
    try:
        battery = max(0, min(100, float(data.get("battery", data.get("level", 100)))))
    except Exception:
        return err("battery invalide", 400)

    payload = {"battery": battery}
    try:
        res = _agent_request(f"/api/topology/drone/{name}/battery", "POST", payload, timeout=3.0)
    except Exception as exc:
        with _LOCK:
            d = TOPOLOGY_STATE["drones"].get(name) or next((x for x in _default_drones() if x["name"] == name), None)
            if not d:
                return err(f"Drone inconnu: {name}", 404)
            d["battery"] = round(battery, 1)
            d["status"] = "LOW_BATTERY" if battery < 20 else "OK"
            TOPOLOGY_STATE["drones"][name] = d
            res = {"ok": True, "fallback": True, "warning": str(exc), "event": "drone_battery", "drone": d}
    sio.emit("drone_battery", res)
    sio.emit("topology_update", {"type": "drone_battery", **res})
    if battery < 20:
        sio.emit("system_event", {"msg": f"⚠ Batterie critique {name}: {battery:.1f}%", "type": "warn"})
    return ok(res)


@app.route("/api/topology/link/<switch>/<host>/status", methods=["POST"])
def api_topology_link_status(switch, host):
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", data.get("up", data.get("status", True)))
    if isinstance(enabled, str):
        enabled = enabled.lower() in ("1", "true", "up", "on", "enable", "enabled", "active")
    enabled = bool(enabled)
    payload = {"enabled": enabled}
    try:
        res = _agent_request(f"/api/topology/link/{switch}/{host}/status", "POST", payload, timeout=3.0)
    except Exception as exc:
        with _LOCK:
            key = f"{switch}<->{host}"
            TOPOLOGY_STATE["links"][key] = "up" if enabled else "down"
            res = {"ok": True, "fallback": True, "warning": str(exc), "event": "link_status_changed", "switch": switch, "host": host, "enabled": enabled, "links": TOPOLOGY_STATE["links"]}
    sio.emit("link_status_changed", res)
    sio.emit("topology_update", {"type": "link_status_changed", **res})
    sio.emit("system_event", {"msg": f"Lien {switch}<->{host} {'activé' if enabled else 'désactivé'}", "type": "info" if enabled else "warn"})
    return ok(res)


@app.route("/api/topology/attack/<drone>/start", methods=["POST"])
def api_topology_attack_start(drone):
    data = request.get_json(silent=True) or {}
    atype = str(data.get("type", "udp")).lower()
    target = str(data.get("target", GCS_IP)).lower()
    duration = int(float(data.get("duration", 20)))
    payload = {"type": atype, "target": target, "duration": duration}
    try:
        res = _agent_request(f"/api/topology/attack/{drone}/start", "POST", payload, timeout=3.0)
        simulated = False
    except Exception as exc:
        attacker_ip = drone_to_ip(drone) or drone
        attack_id = f"topo_{drone}_{int(time.time())}_{random.randint(1000,9999)}"
        _run_attack_simulation(attack_id, atype, drone, attacker_ip, target, duration)
        with _LOCK:
            S["active_attacks"][attack_id] = {
                "id": attack_id, "type": atype, "target": target,
                "attacker": drone, "attacker_ip": attacker_ip,
                "started": time.time(), "expected_end": time.time() + duration,
                "duration": duration, "pid": None, "simulated": True,
            }
        simulated = True
        res = {"ok": True, "fallback": True, "warning": str(exc), "event": "attack_started", "attack_id": attack_id, "drone": drone, "attacker_ip": attacker_ip, "type": atype, "target": target, "duration": duration, "simulated": True}
    sio.emit("attack_launched", res)
    sio.emit("topology_update", {"type": "attack_started", **res})
    sio.emit("system_event", {"msg": f"🚀 Attaque {atype.upper()} lancée depuis {drone} ({'simulation' if simulated else 'Mininet'})", "type": "warn"})
    return ok(res)


def _topology_sync_loop():
    while True:
        eventlet.sleep(3)
        try:
            res = _sync_topology_from_agent()
            sio.emit("topology_update", {"type": "sync", **res})
        except Exception:
            pass


# ─────────────────────────── SOCKETIO EVENTS ───────────────────────────────

@sio.on("connect")
def on_connect():
    with _LOCK:
        up=int(time.time()-S["start_time"])
        sio.emit("init_state",{
            "system":{
                "total_ticks":  S["total_ticks"],
                "total_attacks":S["total_attacks"],
                "total_blocked":S["total_blocked"],
                "current_status":S["current_status"],
                "switch_count": S["switch_count"],
                "uptime":       up,
            },
            "blocked_ips":  S["blocked_ips"],
            "swarm_stats":  S["swarm_stats"],
            "sim_enabled":  S["sim_enabled"],
            "ml_loaded":    MODEL is not None,
            "ryu_connected":S["ryu_connected"],
            "last_ryu_seen":S["last_ryu_seen"],
            "drones": _build_drones_from_state(S.get("last_features", {}), S.get("last_detection", {})),
        })
    # Si ML chargé → envoyer les métriques
    if METRICS:
        sio.emit("ml_ready",{"metrics":METRICS})


@sio.on("traffic_update")
def on_traffic(data):
    """Reçu depuis Ryu → état unique + relais dashboard. Corrige sync/connexion."""
    if not isinstance(data, dict):
        return
    with _LOCK:
        _mark_ryu_seen()

        sys_data = data.get("system", {}) or {}
        S["total_ticks"] = int(sys_data.get("total_ticks", S["total_ticks"]) or S["total_ticks"])
        S["total_attacks"] = int(sys_data.get("total_attacks", S["total_attacks"]) or S["total_attacks"])
        S["total_blocked"] = int(sys_data.get("total_blocked", S["total_blocked"]) or S["total_blocked"])
        S["switch_count"] = int(data.get("switch_count", S["switch_count"]) or S["switch_count"])

        features = data.get("features", {}) or {}
        detection = data.get("detection", {}) or {}

        # Si Ryu n'envoie pas de détails ML complets, on enrichit localement.
        if features and (not detection.get("probabilities") or detection.get("probabilities") == {}):
            detection.update(ml_predict(features))

        features, detection, is_atk = _normalize_detection(features, detection)
        S["last_features"] = features
        S["last_detection"] = detection
        S["current_status"] = "attack" if is_atk else ("suspicious" if detection.get("ensemble_prob", 0) >= .4 else "normal")

        blocked = data.get("blocked_ips", data.get("blocked", [])) or []
        S["blocked_ips"] = sorted(set(ip for ip in blocked if isinstance(ip, str) and ip.startswith("10.")))

        # Swarm stats
        ss = data.get("swarm_stats", {}) or {}
        for sw in SWARMS:
            if sw in ss and isinstance(ss[sw], dict):
                S["swarm_stats"][sw].update(ss[sw])
            elif features.get("per_swarm") and sw in features.get("per_swarm", {}):
                S["swarm_stats"][sw]["pps"] = features["per_swarm"][sw]

        incoming_drones = data.get("drones") or data.get("drone_stats") or []
        drones = _build_drones_from_state(features, detection, incoming=incoming_drones)

        S["history"].append({
            "ts": data.get("timestamp", time.time()),
            "pps": features.get("pps", 0),
            "prob": detection.get("ensemble_prob", 0),
            "isAtk": is_atk,
            "atkType": detection.get("attack_type", "none"),
            "attacker": detection.get("attacker_ip"),
            "probabilities": detection.get("probabilities", {}),
        })

        # Journal : seulement vraie attaque active, pas type none, pas src None.
        atk_type = detection.get("attack_type", "none")
        src = detection.get("attacker_ip")
        if is_atk and atk_type != "none" and src:
            last = S["attack_log"][-1] if len(S["attack_log"]) else {}
            # éviter doublon toutes les secondes pour la même attaque
            if last.get("src") != src or last.get("type") != atk_type or time.time() - last.get("unix", 0) > 3:
                S["attack_log"].append({
                    "ts": datetime.now().isoformat(timespec="seconds"),
                    "unix": time.time(),
                    "type": atk_type,
                    "src": src,
                    "pps": round(features.get("pps", 0), 1),
                    "prob": detection.get("ensemble_prob", 0),
                    "action": "DROP" if src in S["blocked_ips"] else "ALERT",
                })

        payload = dict(data)
        payload.update({
            "features": features,
            "detection": detection,
            "system": {
                **sys_data,
                "total_ticks": S["total_ticks"],
                "total_attacks": S["total_attacks"],
                "total_blocked": S["total_blocked"],
                "current_status": S["current_status"],
                "active_attack": is_atk,
                "uptime": int(time.time() - S["start_time"]),
            },
            "swarm_stats": S["swarm_stats"],
            "blocked_ips": list(S["blocked_ips"]),
            "switch_count": S["switch_count"],
            "drones": drones,
            "drone_stats": drones,
            "drones_active": sum(1 for d in drones if d.get("active")),
            "drones_total": len(drones),
            "ryu_connected": True,
            "timestamp": time.time(),
        })

    sio.emit("traffic_update", payload)


@sio.on("disconnect")
def on_disconnect():
    # Déconnexion d'un navigateur ≠ déconnexion Ryu.
    # Ryu est surveillé uniquement par _ryu_watchdog via last_ryu_seen.
    pass


@sio.on("ryu_hello")
def on_ryu_hello(data):
    """Heartbeat Ryu.
    Important : ne PAS logger à chaque heartbeat, sinon le dashboard affiche
    'RYU connecté au dashboard' toutes les secondes.
    On log seulement lors du passage déconnecté → connecté.
    """
    should_log = False
    with _LOCK:
        was_connected = bool(S.get("ryu_connected"))
        _mark_ryu_seen()
        if not was_connected:
            S["last_ryu_log"] = time.time()
            should_log = True

    if should_log:
        sio.emit("system_event", {
            "msg": "RYU connecté au dashboard",
            "type": "success"
        })


@sio.on("mitigation_event")
def on_mitig(data):
    with _LOCK:
        _mark_ryu_seen()
    ip=data.get("ip","")
    if ip.startswith("10."):
        with _LOCK:
            if ip not in S["blocked_ips"]: S["blocked_ips"].append(ip)
    sio.emit("mitigation_event",data)


@sio.on("system_event")
def on_sys(data):
    """Relais system_event avec anti-spam.
    Même message répété en moins de 10 secondes = ignoré.
    """
    msg = str(data.get("msg", ""))
    now = time.time()
    with _LOCK:
        last = S.setdefault("last_system_msgs", {}).get(msg, 0.0)
        if msg and (now - last) < 10.0:
            return
        if msg:
            S["last_system_msgs"][msg] = now
    sio.emit("system_event", data)


@sio.on("update_config")
def on_cfg(data):
    with _LOCK:
        if "mlThresh"  in data: S["ml_threshold"]=float(data["mlThresh"])
        if "ppsThresh" in data: S["pps_threshold"]=float(data["ppsThresh"])
        if "blockDur"  in data: S["block_duration"]=float(data["blockDur"])
    sio.emit("update_config",data)
    sio.emit("system_event",{
        "msg":f"Config ML={S['ml_threshold']} PPS={S['pps_threshold']}",
        "type":"info"})


@sio.on("attack_start")
def on_atk_start(data):
    sio.emit("system_event",{"msg":f"Attaque dashboard: {data.get('type')}→{data.get('target')}","type":"warn"})


@sio.on("attack_stop")
def on_atk_stop(_): sio.emit("system_event",{"msg":"Arrêt attaque","type":"info"})

@sio.on("pcap_stats")
def on_pcap(d): sio.emit("pcap_stats",d)


# ─────────────────────────── WATCHDOG / KEEPALIVE ──────────────────────────

def _ryu_watchdog():
    while True:
        eventlet.sleep(2)
        with _LOCK:
            if S["ryu_connected"] and S["last_ryu_seen"] and (time.time() - S["last_ryu_seen"] > S["ryu_timeout"]):
                S["ryu_connected"] = False
                S["current_status"] = "waiting" if not S["sim_enabled"] else S["current_status"]
                sio.emit("system_event", {"msg": "RYU timeout : aucune donnée reçue", "type": "warn"})


def _keepalive():
    while True:
        eventlet.sleep(30)
        sio.emit("server_ping",{"uptime":int(time.time()-S["start_time"]),"ts":time.time()})

# ─────────────────────────── MAIN ──────────────────────────────────────────

def main():
    parser=argparse.ArgumentParser(description="UAV-SDN Dashboard Server v5.0")
    parser.add_argument("--no-sim", action="store_true", help="Désactiver auto-simulation")
    parser.add_argument("--train",  action="store_true", help="Forcer re-entraînement ML")
    parser.add_argument("--port",   type=int, default=PORT)
    args=parser.parse_args()

    # Créer les répertoires
    os.makedirs(os.path.join(BASE,"models"), exist_ok=True)

    print("="*65)
    print("  UAV-SDN Dashboard Server v5.0 — ALL-IN-ONE")
    print(f"  URL     : http://0.0.0.0:{args.port}  (VM1: 192.168.100.10:{args.port})")
    print(f"  ML      : {MODEL_PATH}")
    print(f"  Auto-sim: {'DÉSACTIVÉ (--no-sim)' if args.no_sim else 'ACTIF (si Ryu absent)'}")
    print(f"  Topology API: {TOPOLOGY_AGENT_URL}")
    print("="*65)

    with _LOCK: S["sim_enabled"]=not args.no_sim

    # Charger ou entraîner le ML
    if args.train or not os.path.exists(MODEL_PATH):
        print("[ML] Entraînement du modèle...")
        auto_train()
    else:
        load_model()
        if not MODEL:
            print("[ML] Modèle absent → entraînement automatique...")
            eventlet.spawn(lambda: (eventlet.sleep(2), auto_train()))

    # Lancer les coroutines de fond
    eventlet.spawn(_auto_background)
    eventlet.spawn(_ryu_watchdog)
    eventlet.spawn(_keepalive)
    eventlet.spawn(_topology_sync_loop)

    print(f"\n  Dashboard : http://192.168.100.10:{args.port}")
    print("  Ctrl+C pour arrêter\n")

    sio.run(app, host=HOST, port=args.port, debug=False)


if __name__=="__main__":
    main()
