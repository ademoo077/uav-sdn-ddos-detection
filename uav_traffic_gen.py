#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 uav_traffic_gen.py — Générateur de trafic UAV réaliste
================================================================================
 Simule les flux réels d'un drone autonome :
   • TELEMETRY (MAVLink-like) : UDP 14550 → GCS @ 10 Hz, ~80 octets
   • VIDEO STREAM             : UDP 5004 (RTP) → Edge @ 25 fps, MJPEG ~ 8 KB/frame
   • HEARTBEAT                : UDP 14555 → GCS @ 1 Hz
   • GPS BROADCAST            : UDP 14560 (multicast intra-essaim) @ 2 Hz
   • MISSION COMMANDS         : TCP 5760 ↔ GCS (sporadique, idle)
   • MESH COORDINATION        : UDP 7700 entre drones de l'essaim @ 5 Hz

 Modes :
   --role gcs    : récepteur sur GCS (loggue ce qui arrive)
   --role edge   : récepteur de stream vidéo
   --role drone  : émetteur (un drone)

 Utilisation autonome :
   # Sur la GCS :
   python3 uav_traffic_gen.py --role gcs --listen 14550

   # Sur un drone :
   python3 uav_traffic_gen.py --role drone --name recon1 --swarm recon \
       --gcs 10.0.0.100 --edge 10.0.0.200

================================================================================
"""

import argparse
import json
import math
import os
import random
import socket
import struct
import sys
import threading
import time

# ─── PORTS / CONSTANTES ───────────────────────────────────────────────────────
PORT_TELEMETRY = 14550   # MAVLink-like vers GCS
PORT_HEARTBEAT = 14555   # Heartbeat vers GCS
PORT_GPS       = 14560   # GPS broadcast intra-essaim
PORT_VIDEO     = 5004    # RTP vidéo vers edge
PORT_MISSION   = 5760    # Commandes TCP
PORT_MESH      = 7700    # Coordination intra-essaim

# Tailles de paquets typiques (octets)
SIZE_TELEMETRY = 80
SIZE_HEARTBEAT = 32
SIZE_GPS       = 64
SIZE_VIDEO_PKT = 1200    # MTU-friendly RTP
SIZE_MESH      = 96

# Fréquences (Hz)
RATE_TELEMETRY = 10
RATE_HEARTBEAT = 1
RATE_GPS       = 2
RATE_VIDEO_FPS = 25
RATE_MESH      = 5

# Plan IPs essaims (correspond à topo_expert_uav.py)
SWARM_IPS = {
    "recon": ["10.0.0.11", "10.0.0.12", "10.0.0.13"],
    "surv":  ["10.0.0.21", "10.0.0.22", "10.0.0.23"],
    "logi":  ["10.0.0.31", "10.0.0.32", "10.0.0.33"],
}

# ──────────────────────────────────────────────────────────────────────────────


# ══ Émetteurs (côté drone) ════════════════════════════════════════════════════

def _make_telemetry_packet(drone_name, seq, gps):
    """Construit un paquet de télémétrie MAVLink-like."""
    payload = {
        "drone":    drone_name,
        "seq":      seq,
        "lat":      gps[0],
        "lon":      gps[1],
        "alt":      gps[2],
        "vx":       round(random.uniform(-5, 5), 2),
        "vy":       round(random.uniform(-5, 5), 2),
        "vz":       round(random.uniform(-1, 1), 2),
        "roll":     round(random.uniform(-15, 15), 1),
        "pitch":    round(random.uniform(-15, 15), 1),
        "yaw":      round(random.uniform(0, 359), 1),
        "battery":  round(100 - seq * 0.001, 2),
        "mode":     "AUTO",
        "ts":       time.time(),
    }
    data = json.dumps(payload).encode()
    # Padding pour atteindre SIZE_TELEMETRY
    if len(data) < SIZE_TELEMETRY:
        data += b" " * (SIZE_TELEMETRY - len(data))
    return data[:SIZE_TELEMETRY]


def _telemetry_loop(drone_name, gcs_ip):
    """Envoi continu de télémétrie @ 10 Hz."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    # Position GPS simulée (Algiers ~ 36.75N, 3.06E)
    base_lat, base_lon, base_alt = 36.7525, 3.0420, 50.0
    interval = 1.0 / RATE_TELEMETRY

    while True:
        try:
            seq += 1
            # Petit déplacement pseudo-circulaire
            t = seq * interval
            lat = base_lat + 0.0001 * math.sin(t * 0.1)
            lon = base_lon + 0.0001 * math.cos(t * 0.1)
            alt = base_alt + 5 * math.sin(t * 0.05)
            pkt = _make_telemetry_packet(drone_name, seq, (lat, lon, alt))
            sock.sendto(pkt, (gcs_ip, PORT_TELEMETRY))
            time.sleep(interval)
        except Exception as e:
            print(f"[telemetry] {e}", file=sys.stderr)
            time.sleep(1)


def _heartbeat_loop(drone_name, gcs_ip):
    """Heartbeat @ 1 Hz vers GCS."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    while True:
        try:
            seq += 1
            data = struct.pack("!I", seq) + drone_name.encode().ljust(28, b"\x00")
            sock.sendto(data, (gcs_ip, PORT_HEARTBEAT))
            time.sleep(1.0 / RATE_HEARTBEAT)
        except Exception as e:
            print(f"[heartbeat] {e}", file=sys.stderr)
            time.sleep(2)


def _video_loop(drone_name, edge_ip):
    """Stream vidéo simulé @ 25 fps en chunks RTP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    frame_id = 0
    interval = 1.0 / RATE_VIDEO_FPS
    # Frame ~ 8KB → 7 paquets de 1200 octets
    chunks_per_frame = 7

    while True:
        try:
            frame_id += 1
            for chunk in range(chunks_per_frame):
                # En-tête RTP simplifié (12 octets)
                rtp_header = struct.pack("!BBHII",
                    0x80, 96, frame_id & 0xFFFF,
                    int(time.time() * 90000) & 0xFFFFFFFF, 0xDEADBEEF)
                payload = rtp_header + os.urandom(SIZE_VIDEO_PKT - 12)
                sock.sendto(payload, (edge_ip, PORT_VIDEO))
            time.sleep(interval)
        except Exception as e:
            print(f"[video] {e}", file=sys.stderr)
            time.sleep(1)


def _gps_broadcast_loop(drone_name, swarm):
    """Broadcast GPS aux drones de l'essaim @ 2 Hz."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    seq = 0
    interval = 1.0 / RATE_GPS

    peers = [ip for ip in SWARM_IPS.get(swarm, [])]
    while True:
        try:
            seq += 1
            payload = json.dumps({
                "drone": drone_name,
                "seq":   seq,
                "lat":   36.75 + random.uniform(-0.001, 0.001),
                "lon":   3.04 + random.uniform(-0.001, 0.001),
                "alt":   50 + random.uniform(-5, 5),
                "ts":    time.time(),
            }).encode()
            payload = payload.ljust(SIZE_GPS, b" ")[:SIZE_GPS]
            for peer in peers:
                if peer != _self_ip():
                    sock.sendto(payload, (peer, PORT_GPS))
            time.sleep(interval)
        except Exception:
            time.sleep(2)


def _mesh_coord_loop(drone_name, swarm):
    """Coordination intra-essaim @ 5 Hz (formation, évitement)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    interval = 1.0 / RATE_MESH
    peers = SWARM_IPS.get(swarm, [])

    while True:
        try:
            seq += 1
            payload = json.dumps({
                "type": "FORMATION",
                "drone": drone_name,
                "seq": seq,
                "role": random.choice(["LEADER", "FOLLOWER", "WINGMAN"]),
                "target_dist": round(random.uniform(5, 15), 1),
                "ts": time.time(),
            }).encode()
            payload = payload.ljust(SIZE_MESH, b" ")[:SIZE_MESH]
            for peer in peers:
                if peer != _self_ip():
                    sock.sendto(payload, (peer, PORT_MESH))
            time.sleep(interval)
        except Exception:
            time.sleep(2)


def _mission_keepalive(drone_name, gcs_ip):
    """Connexion TCP persistante (commande de mission, idle)."""
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((gcs_ip, PORT_MISSION))
                while True:
                    # ACK périodique
                    s.sendall(b"ACK " + drone_name.encode() + b"\n")
                    time.sleep(15)
        except Exception:
            time.sleep(5)   # retry


def _self_ip():
    """IP locale (ignore loopback)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ══ Récepteurs (GCS / Edge) ═══════════════════════════════════════════════════

def run_listener(role, port):
    """Récepteur UDP qui loggue ce qui arrive."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))

    counters = {"pkts": 0, "bytes": 0}
    last_report = time.time()

    print(f"[{role}] écoute UDP :{port}")

    # Pour le rôle GCS : aussi accepter mission TCP
    if role == "gcs":
        threading.Thread(target=_tcp_mission_listener, daemon=True).start()
        threading.Thread(target=_listener_thread,
                         args=(PORT_HEARTBEAT, "heartbeat", counters),
                         daemon=True).start()

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            counters["pkts"]  += 1
            counters["bytes"] += len(data)

            now = time.time()
            if now - last_report >= 5.0:
                pps  = counters["pkts"]  / (now - last_report)
                kbps = counters["bytes"] * 8 / 1000 / (now - last_report)
                print(f"[{role}] :{port}  {pps:6.1f} pps  {kbps:8.1f} kbps")
                counters["pkts"]  = 0
                counters["bytes"] = 0
                last_report       = now
        except Exception as e:
            print(f"[{role}] {e}", file=sys.stderr)
            time.sleep(1)


def _listener_thread(port, label, _counters):
    """Récepteur secondaire (utilisé pour heartbeat)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    while True:
        try:
            s.recvfrom(1024)
        except Exception:
            time.sleep(1)


def _tcp_mission_listener():
    """Accepte les connexions TCP de mission."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT_MISSION))
    s.listen(20)
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=_handle_mission, args=(conn,),
                             daemon=True).start()
        except Exception:
            time.sleep(1)


def _handle_mission(conn):
    try:
        while True:
            data = conn.recv(256)
            if not data:
                break
    except Exception:
        pass
    finally:
        conn.close()


# ══ MAIN ══════════════════════════════════════════════════════════════════════

def run_drone(name, swarm, gcs_ip, edge_ip):
    """Lance tous les flux d'un drone en parallèle."""
    print(f"[drone] {name} (essaim {swarm}) → GCS={gcs_ip} edge={edge_ip}")

    threads = [
        threading.Thread(target=_telemetry_loop,    args=(name, gcs_ip),  daemon=True),
        threading.Thread(target=_heartbeat_loop,    args=(name, gcs_ip),  daemon=True),
        threading.Thread(target=_video_loop,        args=(name, edge_ip), daemon=True),
        threading.Thread(target=_gps_broadcast_loop,args=(name, swarm),   daemon=True),
        threading.Thread(target=_mesh_coord_loop,   args=(name, swarm),   daemon=True),
        threading.Thread(target=_mission_keepalive, args=(name, gcs_ip),  daemon=True),
    ]
    for t in threads:
        t.start()

    # Maintien du processus
    while True:
        time.sleep(60)


def main():
    parser = argparse.ArgumentParser(description="Générateur de trafic UAV réaliste")
    parser.add_argument("--role", choices=["drone", "gcs", "edge"], required=True)
    parser.add_argument("--name", help="Nom du drone (ex: recon1)")
    parser.add_argument("--swarm", choices=list(SWARM_IPS.keys()),
                        help="Essaim du drone")
    parser.add_argument("--gcs", default="10.0.0.100",
                        help="IP du GCS")
    parser.add_argument("--edge", default="10.0.0.200",
                        help="IP de l'edge server")
    parser.add_argument("--listen", type=int, default=14550,
                        help="Port UDP à écouter (rôles gcs/edge)")
    args = parser.parse_args()

    try:
        if args.role == "drone":
            if not args.name or not args.swarm:
                parser.error("--name et --swarm requis pour le rôle drone")
            run_drone(args.name, args.swarm, args.gcs, args.edge)
        else:
            run_listener(args.role, args.listen)
    except KeyboardInterrupt:
        print(f"\n[{args.role}] arrêt.")


if __name__ == "__main__":
    main()
