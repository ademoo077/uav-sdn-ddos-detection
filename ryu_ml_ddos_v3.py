#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ryu_ml_ddos_v3.py — VERSION CORRIGÉE

Corrections:
- dp.id None ne fait plus crasher Ryu.
- pps=0 / flow_count=0 / attacker_ip=None => NORMAL, pas d'alerte.
- Envoi d'un état clair au dashboard : active_attack, drones, drone_stats.
- Séparation attaque active / historique.
- Mitigation DROP sur tous les switches.
"""

import collections
import json
import math
import os
import queue
import sys
import threading
import time

import numpy as np

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, packet
from ryu.ofproto import ofproto_v1_3


DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://192.168.100.10:5000")
MODEL_PATH = os.getenv("MODEL_PATH", "/home/uav/drones/models/ensemble_model.pkl")
METRICS_PATH = os.getenv("METRICS_PATH", "/home/uav/drones/models/metrics.json")

DETECTION_INTERVAL = float(os.getenv("DETECTION_INTERVAL", "1.0"))
ML_THRESHOLD = float(os.getenv("ML_THRESHOLD", "0.65"))
PPS_THRESHOLD = float(os.getenv("PPS_THRESHOLD", "800"))
BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", "300"))

LOG = "[RYU-v3-DETECT-FIX]"

SWARM_MAP = {
    "recon": {"10.0.0.11", "10.0.0.12", "10.0.0.13"},
    "surv": {"10.0.0.21", "10.0.0.22", "10.0.0.23"},
    "logi": {"10.0.0.31", "10.0.0.32", "10.0.0.33"},
}

DRONE_INFO = {
    "10.0.0.11": {"name": "recon1", "swarm": "recon", "altitude": 32, "battery": 94.5},
    "10.0.0.12": {"name": "recon2", "swarm": "recon", "altitude": 34, "battery": 91.2},
    "10.0.0.13": {"name": "recon3", "swarm": "recon", "altitude": 31, "battery": 89.8},
    "10.0.0.21": {"name": "surv1", "swarm": "surv", "altitude": 29, "battery": 93.0},
    "10.0.0.22": {"name": "surv2", "swarm": "surv", "altitude": 33, "battery": 87.6},
    "10.0.0.23": {"name": "surv3", "swarm": "surv", "altitude": 28, "battery": 90.9},
    "10.0.0.31": {"name": "logi1", "swarm": "logi", "altitude": 30, "battery": 92.7},
    "10.0.0.32": {"name": "logi2", "swarm": "logi", "altitude": 35, "battery": 88.0},
    "10.0.0.33": {"name": "logi3", "swarm": "logi", "altitude": 32, "battery": 76.0},
}

WHITELIST_IPS = {"10.0.0.100", "10.0.0.200"}

DPID_TO_SWARM = {
    0x01: "core",
    0xA0: "recon",
    0xA1: "surv",
    0xA2: "logi",
}


def _ip_to_swarm(ip):
    for swarm, ips in SWARM_MAP.items():
        if ip in ips:
            return swarm
    return None


def _safe_dpid(dp):
    if dp is None or getattr(dp, "id", None) is None:
        return None, "unknown"
    return dp.id, f"{dp.id:x}"


_emit_queue = queue.Queue(maxsize=2000)


def emit(event, data):
    try:
        _emit_queue.put_nowait((event, data))
    except queue.Full:
        pass


def _sio_worker():
    try:
        import socketio as sio_lib
    except ImportError:
        print(f"{LOG} python-socketio absent: pip install python-socketio[client]")
        return

    sio = sio_lib.Client(
        reconnection=True,
        reconnection_delay=2,
        reconnection_attempts=0,
        logger=False,
        engineio_logger=False,
    )
    connected = [False]

    @sio.event
    def connect():
        connected[0] = True
        print(f"{LOG} Dashboard connecté : {DASHBOARD_URL}")
        # Connexion initiale : envoyer uniquement ryu_hello.
        # Le dashboard affiche le log une seule fois côté serveur.
        sio.emit("ryu_hello", {"source": "ryu", "ts": time.time(), "controller": "192.168.100.10", "event": "connect"})

    @sio.event
    def disconnect():
        connected[0] = False
        print(f"{LOG} Dashboard déconnecté")

    @sio.on("update_config")
    def on_cfg(data):
        global ML_THRESHOLD, PPS_THRESHOLD, BLOCK_DURATION, DETECTION_INTERVAL
        try:
            if "mlThresh" in data:
                ML_THRESHOLD = float(data["mlThresh"])
            if "ppsThresh" in data:
                PPS_THRESHOLD = float(data["ppsThresh"])
            if "blockDur" in data:
                BLOCK_DURATION = int(float(data["blockDur"]))
            if "detInterval" in data:
                DETECTION_INTERVAL = float(data["detInterval"])
            print(f"{LOG} Config MAJ: ML={ML_THRESHOLD}, PPS={PPS_THRESHOLD}, BLOCK={BLOCK_DURATION}")
        except Exception as e:
            print(f"{LOG} Config error: {e}")

    while True:
        try:
            if not connected[0]:
                try:
                    # WebSocket d'abord, fallback polling si proxy/version bloque le websocket
                    sio.connect(DASHBOARD_URL, transports=["websocket", "polling"], wait_timeout=5)
                except Exception:
                    time.sleep(2)
                    continue

            try:
                event, data = _emit_queue.get(timeout=1.0)
                if connected[0]:
                    sio.emit(event, data)
            except queue.Empty:
                pass

        except Exception:
            connected[0] = False
            time.sleep(2)


threading.Thread(target=_sio_worker, daemon=True, name="sio-worker").start()


class DDoSDetectorV3(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.datapaths = {}
        self.mac_to_port = {}

        self.blocked_ips = set()
        self.block_timers = {}

        self.total_ticks = 0
        self.total_attacks = 0
        self.total_blocked = 0
        self.start_time = time.time()

        self.prev_flow_stats = {}
        self.flow_window = collections.deque(maxlen=300)
        self.attack_history = collections.deque(maxlen=300)

        self.swarm_stats = {
            swarm: {"pps": 0, "attacks": 0, "active": len(ips)}
            for swarm, ips in SWARM_MAP.items()
        }

        self.model = None
        self.metrics = {}
        self._load_model()

        self._monitor_thread = hub.spawn(self._monitor_loop)

        print(f"{LOG} DDoS Detector corrigé prêt")
        print(f"{LOG} Modèle ML : {'chargé' if self.model else 'mode seuil'}")
        print(f"{LOG} Whitelist : {WHITELIST_IPS}")

    def _load_model(self):
        if not HAS_JOBLIB:
            print(f"{LOG} joblib absent")
            return

        try:
            wrapper_path = "/home/uav/drones/lstm_wrapper.py"
            if os.path.exists(wrapper_path):
                import importlib.util
                spec = importlib.util.spec_from_file_location("lstm_wrapper", wrapper_path)
                mod = importlib.util.module_from_spec(spec)
                sys.modules["lstm_wrapper"] = mod
                spec.loader.exec_module(mod)

            if os.path.exists(MODEL_PATH):
                self.model = joblib.load(MODEL_PATH)
                print(f"{LOG} Modèle chargé : {MODEL_PATH}")
            else:
                print(f"{LOG} Modèle introuvable : {MODEL_PATH}")

            if os.path.exists(METRICS_PATH):
                with open(METRICS_PATH, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)

        except Exception as e:
            print(f"{LOG} Erreur chargement modèle : {e}")
            self.model = None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        dpid, dpid_str = _safe_dpid(dp)

        if dpid is None:
            print(f"{LOG} Switch sans DPID ignoré")
            return

        ofp = dp.ofproto
        par = dp.ofproto_parser

        self.datapaths[dpid] = dp
        self.mac_to_port.setdefault(dpid, {})

        match = par.OFPMatch()
        actions = [par.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)

        arp_match = par.OFPMatch(eth_type=0x0806)
        self._add_flow(dp, 10, arp_match, [par.OFPActionOutput(ofp.OFPP_FLOOD)])

        # IMPORTANT :
        # On whitelist seulement la SOURCE GCS/EDGE.
        # Ne PAS installer ipv4_dst=10.0.0.100/200 en OFPP_NORMAL,
        # sinon tout le trafic drone -> GCS/Edge est agrégé dans une règle
        # sans ipv4_src, donc attacker_ip=None et le ML ignore l'attaque.
        for wl_ip in WHITELIST_IPS:
            self._add_flow(dp, 100, par.OFPMatch(eth_type=0x0800, ipv4_src=wl_ip),
                           [par.OFPActionOutput(ofp.OFPP_NORMAL)])

        swarm = DPID_TO_SWARM.get(dpid, f"dpid-{dpid_str}")
        print(f"{LOG} Switch dpid={dpid_str} ({swarm}) connecté")
        emit("system_event", {
            "msg": f"Switch {dpid_str} ({swarm}) connecté",
            "type": "info",
        })

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        dpid, dpid_str = _safe_dpid(dp)

        if dp is None:
            return

        if ev.state == MAIN_DISPATCHER:
            if dpid is not None:
                self.datapaths[dpid] = dp

        elif ev.state == DEAD_DISPATCHER:
            if dpid is not None:
                self.datapaths.pop(dpid, None)
                self.prev_flow_stats.pop(dpid, None)

            emit("system_event", {
                "msg": f"Switch {dpid_str} déconnecté",
                "type": "warn",
            })

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid, _ = _safe_dpid(dp)

        if dpid is None:
            return

        ofp = dp.ofproto
        par = dp.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src, dst = eth.src, eth.dst
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions = [par.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            ip4 = pkt.get_protocol(ipv4.ipv4)
            if ip4:
                if ip4.src in self.blocked_ips and ip4.src not in WHITELIST_IPS:
                    return

                match_kwargs = {
                    "in_port": in_port,
                    "eth_type": 0x0800,
                    "ipv4_src": ip4.src,
                    "ipv4_dst": ip4.dst,
                }
                # ip4.proto : 6=TCP, 17=UDP, 1=ICMP.
                # Cela permet au module ML de calculer syn_ratio/udp_ratio/icmp_ratio.
                if getattr(ip4, "proto", 0) in (1, 6, 17):
                    match_kwargs["ip_proto"] = ip4.proto

                match = par.OFPMatch(**match_kwargs)
                self._add_flow(dp, 5, match, actions, idle_timeout=30)
            else:
                match = par.OFPMatch(in_port=in_port, eth_dst=dst)
                self._add_flow(dp, 2, match, actions, idle_timeout=30)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = par.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        dp.send_msg(out)

    def _add_flow(self, dp, priority, match, actions, hard_timeout=0, idle_timeout=0):
        ofp = dp.ofproto
        par = dp.ofproto_parser
        inst = [par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = par.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
        )
        dp.send_msg(mod)

    def _monitor_loop(self):
        while True:
            hub.sleep(DETECTION_INTERVAL)
            self.total_ticks += 1
            emit("ryu_hello", {"source": "ryu", "ts": time.time(), "ticks": self.total_ticks})

            now = time.time()
            expired = [ip for ip, ts in list(self.block_timers.items()) if now > ts]

            for ip in expired:
                self.blocked_ips.discard(ip)
                self.block_timers.pop(ip, None)
                emit("system_event", {
                    "msg": f"Déblocage automatique : {ip}",
                    "type": "info",
                })

            for dp in list(self.datapaths.values()):
                try:
                    par = dp.ofproto_parser
                    req = par.OFPFlowStatsRequest(dp)
                    dp.send_msg(req)
                except Exception:
                    pass

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dp = ev.msg.datapath
        dpid, dpid_str = _safe_dpid(dp)

        if dpid is None:
            return

        now = time.time()
        flows = ev.msg.body

        features = self._extract_features(flows, dpid, now)
        detection = self._run_detection(features)
        is_attack = bool(detection["is_attack"])
        attack_type = self._classify_attack(features, is_attack)
        detection["attack_type"] = attack_type

        for swarm in SWARM_MAP:
            self.swarm_stats[swarm]["pps"] = features["per_swarm"].get(swarm, 0)

        if is_attack:
            attacker = detection.get("attacker_ip")
            if attacker and attacker not in WHITELIST_IPS:
                self.total_attacks += 1

                victim_swarm = _ip_to_swarm(attacker)
                if victim_swarm:
                    self.swarm_stats[victim_swarm]["attacks"] += 1

                self._block_ip(dp, attacker)

                incident = {
                    "time": time.strftime("%H:%M:%S"),
                    "timestamp": now,
                    "attacker_ip": attacker,
                    "attacker": attacker,
                    "target": "10.0.0.100",
                    "type": attack_type,
                    "attack_type": attack_type,
                    "pps": features["pps"],
                    "prob": detection["ensemble_prob"],
                    "action": "DROP",
                }
                self.attack_history.append(incident)
                emit("attack_event", incident)

        uptime = int(now - self.start_time)
        drones = self._build_drone_status(features, detection)

        payload = {
            "features": features,
            "detection": {
                **detection,
                "method": "ML_Ensemble" if self.model else "threshold",
                "active_attack": is_attack,
            },
            "system": {
                "total_ticks": self.total_ticks,
                "total_attacks": self.total_attacks,
                "total_blocked": len(self.blocked_ips),
                "current_status": "attack" if is_attack else "normal",
                "active_attack": is_attack,
                "uptime": uptime,
            },
            "swarm_stats": self.swarm_stats,
            "blocked_ips": list(self.blocked_ips),
            "switch_count": len(self.datapaths),
            "drones": drones,
            "drone_stats": drones,
            "drones_active": sum(1 for d in drones if d["active"]),
            "drones_total": len(drones),
            "attack_history": list(self.attack_history)[-20:],
            "dpid": dpid,
            "swarm": DPID_TO_SWARM.get(dpid, f"dpid-{dpid_str}"),
            "ryu_connected": True,
            "source": "ryu",
            "timestamp": now,
        }

        self.flow_window.append({
            "ts": now,
            "dpid": dpid,
            "pps": features["pps"],
            "prob": detection["ensemble_prob"],
            "attack": is_attack,
        })

        emit("traffic_update", payload)

        if is_attack:
            print(
                f"{LOG} ⚠ {attack_type} — pps={features['pps']:.0f} "
                f"src={detection.get('attacker_ip')} "
                f"prob={detection['ensemble_prob']:.2f}"
            )

    def _extract_features(self, flows, dpid, now):
        total_pkts = 0
        total_bytes = 0
        syn_pkts = 0
        udp_pkts = 0
        icmp_pkts = 0
        src_ips = collections.Counter()
        per_swarm = collections.Counter()
        pkt_sizes = []
        flow_count = 0
        attacker_ip = None

        prev = self.prev_flow_stats.get(dpid, {})
        new_prev = {}

        for f in flows:
            if f.priority == 0:
                continue

            m = f.match
            src_ip = m.get("ipv4_src", "")
            dst_ip = m.get("ipv4_dst", "")
            proto = m.get("ip_proto", 0)
            key = (src_ip, dst_ip, proto)

            old_bytes, old_pkts, old_ts = prev.get(key, (0, 0, now - DETECTION_INTERVAL))
            delta_pkts = max(f.packet_count - old_pkts, 0)
            delta_bytes = max(f.byte_count - old_bytes, 0)
            new_prev[key] = (f.byte_count, f.packet_count, now)

            if delta_pkts == 0:
                continue

            flow_count += 1
            total_pkts += delta_pkts
            total_bytes += delta_bytes

            if src_ip and src_ip not in WHITELIST_IPS:
                src_ips[src_ip] += delta_pkts
                swarm = _ip_to_swarm(src_ip)
                if swarm:
                    per_swarm[swarm] += delta_pkts

            if proto == 6:
                # Les flows appris matchent ip_proto=6 mais pas toujours tcp_flags.
                # Pour la démo SYN flood, on compte le trafic TCP comme SYN-like.
                syn_pkts += delta_pkts
            elif proto == 17:
                udp_pkts += delta_pkts
            elif proto == 1:
                icmp_pkts += delta_pkts

            pkt_sizes.append(delta_bytes / max(delta_pkts, 1))

        self.prev_flow_stats[dpid] = new_prev

        pps = total_pkts / max(DETECTION_INTERVAL, 0.001)
        unique_srcs = len(src_ips)
        avg_pkt_size = sum(pkt_sizes) / len(pkt_sizes) if pkt_sizes else 512.0

        src_entropy = 1.0
        if src_ips and unique_srcs > 1:
            total = sum(src_ips.values())
            probs = [c / total for c in src_ips.values() if total > 0]
            h = -sum(p * math.log2(p) for p in probs if p > 0)
            max_h = math.log2(unique_srcs)
            src_entropy = min(h / max_h, 1.0) if max_h > 0 else 1.0

        if src_ips:
            attacker_ip = src_ips.most_common(1)[0][0]

        return {
            "pps": round(pps, 2),
            "src_entropy": round(src_entropy, 4),
            "syn_ratio": round(syn_pkts / max(total_pkts, 1), 4),
            "udp_ratio": round(udp_pkts / max(total_pkts, 1), 4),
            "icmp_ratio": round(icmp_pkts / max(total_pkts, 1), 4),
            "unique_srcs": unique_srcs,
            "avg_pkt_size": round(avg_pkt_size, 1),
            "flow_count": flow_count,
            "total_pkts": total_pkts,
            "total_bytes": total_bytes,
            "attacker_ip": attacker_ip,
            "per_swarm": dict(per_swarm),
        }

    def _run_detection(self, features):
        if (
            features.get("total_pkts", 0) <= 0
            or features.get("flow_count", 0) <= 0
            or features.get("attacker_ip") is None
            or features.get("pps", 0) <= 0
        ):
            return {
                "is_attack": False,
                "ensemble_prob": 0.0,
                "probabilities": {
                    "RandomForest": 0.0,
                    "SVM": 0.0,
                    "LSTM": 0.0,
                    "Ensemble": 0.0,
                },
                "attacker_ip": None,
                "active_attack": False,
                "attack_type": "none",
                "ignored_reason": "no_real_traffic",
            }

        X = np.array([[
            features["pps"],
            features["src_entropy"],
            features["syn_ratio"],
            features["udp_ratio"],
            features["icmp_ratio"],
            features["unique_srcs"],
            features["avg_pkt_size"],
            features["flow_count"],
        ]], dtype=float)

        probs_dict = {}
        ensemble_prob = 0.0
        is_attack = False

        if self.model:
            try:
                model_obj = self.model

                if isinstance(model_obj, dict):
                    scaler = model_obj.get("scaler")
                    X_scaled = scaler.transform(X) if scaler else X
                    probs = []

                    for name, mdl in model_obj.items():
                        if name in ("scaler", "feature_names", "metadata", "dataset_size", "trained_at"):
                            continue

                        try:
                            if hasattr(mdl, "predict_proba"):
                                p = float(mdl.predict_proba(X_scaled)[0][1])
                            elif hasattr(mdl, "predict"):
                                p = float(mdl.predict(X_scaled)[0])
                            else:
                                continue

                            probs_dict[name] = round(p, 4)
                            probs.append(p)

                        except Exception as sub_e:
                            probs_dict[name] = 0.0
                            print(f"{LOG} ML submodel {name} ignoré: {sub_e}")

                    if probs:
                        ensemble_prob = sum(probs) / len(probs)
                        is_attack = ensemble_prob >= ML_THRESHOLD
                    else:
                        is_attack, ensemble_prob = self._threshold_detect(features)
                        probs_dict["threshold"] = round(ensemble_prob, 4)

                else:
                    if hasattr(model_obj, "predict_proba"):
                        ensemble_prob = float(model_obj.predict_proba(X)[0][1])
                    elif hasattr(model_obj, "predict"):
                        ensemble_prob = float(model_obj.predict(X)[0])
                    is_attack = ensemble_prob >= ML_THRESHOLD
                    probs_dict["model"] = round(ensemble_prob, 4)

            except Exception as e:
                print(f"{LOG} ML error: {e}")
                is_attack, ensemble_prob = self._threshold_detect(features)
                probs_dict["threshold"] = round(ensemble_prob, 4)

        else:
            is_attack, ensemble_prob = self._threshold_detect(features)
            probs_dict["threshold"] = round(ensemble_prob, 4)

        dangerous_shape = (
            features.get("syn_ratio", 0) > 0.60
            or features.get("udp_ratio", 0) > 0.80
            or features.get("icmp_ratio", 0) > 0.60
            or features.get("src_entropy", 1.0) < 0.25
            or features.get("unique_srcs", 0) > 50
        )

        if features.get("pps", 0) < 5 and not dangerous_shape:
            is_attack = False
            ensemble_prob = min(ensemble_prob, 0.10)

        return {
            "is_attack": bool(is_attack),
            "ensemble_prob": round(float(ensemble_prob), 4),
            "probabilities": probs_dict,
            "attacker_ip": features.get("attacker_ip"),
            "active_attack": bool(is_attack),
            "ignored_reason": None,
        }

    def _threshold_detect(self, f):
        score = 0.0
        if f.get("pps", 0) > PPS_THRESHOLD:
            score += 0.40
        if f.get("src_entropy", 1.0) < 0.30:
            score += 0.25
        if f.get("syn_ratio", 0) > 0.60:
            score += 0.20
        if f.get("udp_ratio", 0) > 0.80:
            score += 0.15
        if f.get("icmp_ratio", 0) > 0.60:
            score += 0.15
        if f.get("unique_srcs", 0) > 50:
            score += 0.10
        return score >= ML_THRESHOLD, min(score, 1.0)

    def _classify_attack(self, features, is_attack):
        if not is_attack:
            return "none"
        if features.get("syn_ratio", 0) > 0.50:
            return "SYN_FLOOD"
        if features.get("udp_ratio", 0) > 0.70:
            return "UDP_FLOOD"
        if features.get("icmp_ratio", 0) > 0.50:
            return "ICMP_FLOOD"
        if features.get("unique_srcs", 0) > 50:
            return "DISTRIBUTED"
        return "GENERIC_DDOS"

    def _build_drone_status(self, features, detection):
        drones = []
        attacker = detection.get("attacker_ip")
        per_swarm = features.get("per_swarm", {})

        for ip, meta in DRONE_INFO.items():
            swarm = meta["swarm"]
            swarm_pps = per_swarm.get(swarm, 0)
            pps = round(swarm_pps / max(len(SWARM_MAP.get(swarm, [])), 1), 2)

            status = "OK"
            risk = 0

            if ip in self.blocked_ips:
                status = "BLOCKED"
                risk = 100
            elif attacker == ip and detection.get("is_attack"):
                status = "ATTACK"
                risk = int(detection.get("ensemble_prob", 0) * 100)
                pps = features.get("pps", pps)
            elif pps > PPS_THRESHOLD / 3:
                status = "SUSPECT"
                risk = 45

            battery = max(0.0, float(meta["battery"]) - (time.time() - self.start_time) / 3600.0)

            drones.append({
                "name": meta["name"],
                "id": meta["name"],
                "ip": ip,
                "swarm": swarm,
                "active": True,
                "pps": pps,
                "altitude": meta["altitude"],
                "battery": round(battery, 1),
                "status": status,
                "risk": risk,
                "blocked": ip in self.blocked_ips,
            })

        return drones

    def _block_ip(self, dp, ip):
        if not ip or ip in WHITELIST_IPS or ip in self.blocked_ips:
            return

        self.blocked_ips.add(ip)
        self.total_blocked += 1
        self.block_timers[ip] = time.time() + BLOCK_DURATION

        par = dp.ofproto_parser
        match = par.OFPMatch(eth_type=0x0800, ipv4_src=ip)

        for d in list(self.datapaths.values()):
            try:
                self._add_flow(d, 200, match, [], hard_timeout=int(BLOCK_DURATION))
            except Exception:
                pass

        swarm = _ip_to_swarm(ip) or "external"

        print(f"{LOG} DROP installé : {ip} ({swarm}) pendant {BLOCK_DURATION}s")

        emit("mitigation_event", {
            "ip": ip,
            "swarm": swarm,
            "duration": BLOCK_DURATION,
            "timestamp": time.time(),
            "action": "DROP",
        })

        emit("system_event", {
            "msg": f"Mitigation OpenFlow : {ip} ({swarm}) bloquée {BLOCK_DURATION}s",
            "type": "warn",
        })
