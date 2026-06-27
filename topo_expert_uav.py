#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 topo_expert_uav.py — Topologie SDN UAV expert multi-essaims (Mininet-WiFi)
================================================================================
 Architecture réaliste :

   ┌─────────────────────────────────────────────────────────────────────┐
   │              GCS Mininet → 10.0.0.100   (VM1=192.168.100.10)          │
   │              Edge Mininet → 10.0.0.200   (VM2=192.168.100.20)                 │
   └────────────────────────────────┬────────────────────────────────────┘
                                    │ (backbone OF1.3)
                            ┌───────┴───────┐
                            │   s1 (core)   │
                            └─┬─────┬─────┬─┘
                              │     │     │
                       ┌──────┘     │     └──────┐
                       │            │            │
                  ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
                  │ ap-recon│  │ ap-surv │  │ ap-logi │
                  └─┬─┬─┬───┘  └─┬─┬─┬───┘  └─┬─┬─┬───┘
                    │ │ │        │ │ │        │ │ │
                  recon1-3    surv1-3       logi1-3   (9 drones)

 Ports / IPs :
   • Backbone   : 10.0.0.0/24     (GCS=.100, Edge=.200, drones=.11-.33)
   • Drones     : 10.0.0.0/24       (recon=10.0.0.10-12, surv=20-22, logi=30-32)
   • Contrôleur : Ryu @ 192.168.100.10:6653 (VM1) (OpenFlow 1.3)

 Lancement :
   sudo python3 topo_expert_uav.py
   sudo python3 topo_expert_uav.py --no-mobility   # statique
   sudo python3 topo_expert_uav.py --controller 192.168.1.42

================================================================================
"""

import argparse
import sys
import time
from mininet.log import setLogLevel, info, warn
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink

try:
    from mn_wifi.net import Mininet_wifi
    from mn_wifi.node import OVSKernelAP
    from mn_wifi.cli import CLI
    from mn_wifi.link import wmediumd
    from mn_wifi.wmediumdConnector import interference
    HAS_WIFI = True
except ImportError:
    warn("*** Mininet-WiFi indisponible — fallback Mininet classique\n")
    from mininet.net import Mininet
    from mininet.cli import CLI
    HAS_WIFI = False

# ─── CONFIGURATION ────────────────────────────────────────────────────────────
# VM1 (Ryu + Dashboard) : 192.168.100.10
# VM2 (Mininet)         : 192.168.100.20
CONTROLLER_IP   = "192.168.100.10"   # IP de la VM1
CONTROLLER_PORT = 6653               # ⚠ Ryu OpenFlow 1.3 = 6653 (pas 6633 !)

# IP plan Mininet (≠ IPs des VMs !)
GCS_IP  = "10.0.0.100/24"    # Ground Control Station (host Mininet)
EDGE_IP = "10.0.0.200/24"    # Edge Server (host Mininet)

# Essaims : (nom, prefix_ip, position_centrale_xyz, mac_prefix)
SWARMS = [
    ("recon", "10.0.0.1",  (60,  60, 30),  "00:00:00:00:01:"),  # Reconnaissance
    ("surv",  "10.0.0.2",  (180, 60, 30),  "00:00:00:00:02:"),  # Surveillance
    ("logi",  "10.0.0.3",  (120, 180, 25), "00:00:00:00:03:"),  # Logistique
]
DRONES_PER_SWARM = 3
# ──────────────────────────────────────────────────────────────────────────────


def build_topology(args):
    """Construit la topologie multi-essaims."""

    setLogLevel("info")

    if HAS_WIFI:
        net = Mininet_wifi(
            controller=RemoteController,
            link=wmediumd,
            wmediumd_mode=interference,
            switch=OVSKernelAP,
        )
    else:
        from mininet.net import Mininet
        net = Mininet(controller=RemoteController, link=TCLink,
                      switch=OVSKernelSwitch, autoSetMacs=True)

    # ─── 1. Contrôleur Ryu distant ─────────────────────────────────────────
    info(f"*** Contrôleur Ryu @ {args.controller}:{CONTROLLER_PORT}\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip=args.controller,
        port=CONTROLLER_PORT,
    )

    # ─── 2. Switch backbone (cœur SDN) ─────────────────────────────────────
    info("*** Switch backbone (s1 — core)\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13", failMode="secure", dpid="0000000000000001")

    # ─── 3. Stations terrestres ────────────────────────────────────────────
    info("*** Ground Control Station (GCS) + Edge Server\n")
    if HAS_WIFI:
        gcs  = net.addHost("gcs",  ip=GCS_IP,  mac="00:00:00:00:99:01")
        edge = net.addHost("edge", ip=EDGE_IP, mac="00:00:00:00:99:02")
    else:
        gcs  = net.addHost("gcs",  ip=GCS_IP,  mac="00:00:00:00:99:01")
        edge = net.addHost("edge", ip=EDGE_IP, mac="00:00:00:00:99:02")

    net.addLink(gcs,  s1, bw=1000, delay="1ms")
    net.addLink(edge, s1, bw=1000, delay="1ms")

    # ─── 4. Essaims de drones ──────────────────────────────────────────────
    aps     = []
    drones  = []

    for swarm_idx, (name, ip_prefix, pos, mac_prefix) in enumerate(SWARMS):
        x0, y0, z0 = pos

        # Access Point dédié à l'essaim (= switch OF de bord)
        ap_name = f"ap-{name}"
        info(f"*** AP {ap_name} (essaim {name})\n")
        if HAS_WIFI:
            ap = net.addAccessPoint(
                ap_name,
                ssid=f"uav-{name}",
                mode="g",
                channel=str(1 + swarm_idx * 5),    # canaux 1, 6, 11
                position=f"{x0},{y0},{z0-20}",
                protocols="OpenFlow13",
                failMode="secure",
                dpid=f"00000000000000{0xA0+swarm_idx:02x}",
            )
        else:
            ap = net.addSwitch(ap_name, protocols="OpenFlow13", failMode="secure",
                              dpid=f"00000000000000{0xA0+swarm_idx:02x}")
        aps.append(ap)

        # Lien AP ↔ backbone (haut débit, faible latence)
        net.addLink(ap, s1, bw=500, delay="2ms")

        # Drones de l'essaim
        for i in range(DRONES_PER_SWARM):
            drone_id = i + 1
            # IP : essaim 1 → 10.0.0.10-12, essaim 2 → 10.0.0.20-22, etc.
            ip4 = f"10.0.0.{(swarm_idx+1)*10 + drone_id}/24"
            mac = f"{mac_prefix}{drone_id:02x}"
            dname = f"{name}{drone_id}"

            # Position en triangle autour du centre de l'essaim
            offset_x = 15 * (i - 1)
            offset_y = 12 * ((i % 2) * 2 - 1)
            px, py, pz = x0 + offset_x, y0 + offset_y, z0

            info(f"***   Drone {dname} ip={ip4}\n")
            if HAS_WIFI:
                drone = net.addStation(
                    dname,
                    ip=ip4,
                    mac=mac,
                    position=f"{px},{py},{pz}",
                    range=80,
                )
            else:
                drone = net.addHost(dname, ip=ip4, mac=mac)
                net.addLink(drone, ap, bw=54, delay="5ms", loss=1)

            drones.append((dname, drone, swarm_idx, name))

    # ─── 5. Configuration WiFi ─────────────────────────────────────────────
    if HAS_WIFI:
        info("*** Configuration noeuds WiFi\n")
        net.setPropagationModel(model="logDistance", exp=3)
        net.configureWifiNodes()

        # Mobilité (drones bougent autour de leur AP)
        if not args.no_mobility:
            info("*** Mobilité activée (drones en patrouille)\n")
            net.startMobility(time=0, mob_rate=0.5)
            for dname, drone, swarm_idx, sname in drones:
                x0, y0, z0 = SWARMS[swarm_idx][2]
                # Patrouille dans un rayon de 40m autour du centre
                net.mobility(drone, 'start', time=1,
                             position=f"{x0-30},{y0-30},{z0}")
                net.mobility(drone, 'stop',  time=600,
                             position=f"{x0+30},{y0+30},{z0}")
            net.stopMobility(time=600)

    # ─── 6. Build & start ──────────────────────────────────────────────────
    info("*** Construction du réseau\n")
    net.build()
    c0.start()
    s1.start([c0])
    for ap in aps:
        ap.start([c0])

    # ─── 7. Bannière de bienvenue ──────────────────────────────────────────
    info("\n" + "=" * 70 + "\n")
    info(" UAV-SDN EXPERT TOPOLOGY — opérationnelle\n")
    info("=" * 70 + "\n")
    info(f"  Contrôleur  : {args.controller}:{CONTROLLER_PORT} (VM1 192.168.100.10)\n")
    info(f"  Backbone    : s1 (dpid=1)  — switches AP : ap-recon, ap-surv, ap-logi\n")
    info(f"  GCS         : 10.0.0.100  (host Mininet)\n")
    info(f"  Edge        : 10.0.0.200  (host Mininet)\n")
    info(f"  Essaims     : {len(SWARMS)} × {DRONES_PER_SWARM} = {len(drones)} drones\n")
    info(f"  IPs drones  : 10.0.0.11-13 (recon) | 10.0.0.21-23 (surv) | 10.0.0.31-33 (logi)\n")
    info("=" * 70 + "\n\n")

    # Test de connectivité initial
    info("*** Test de ping global (peut prendre 10s)\n")
    time.sleep(2)
    net.pingAll(timeout=2)

    # ─── 8. Lancer trafic UAV réaliste en arrière-plan ─────────────────────
    if not args.no_traffic:
        info("\n*** Démarrage du trafic UAV réaliste en arrière-plan\n")
        _start_realistic_traffic(net, drones, gcs, edge)

    # ─── 9. CLI interactive ────────────────────────────────────────────────
    info("\n*** CLI Mininet — commandes utiles :\n")
    info("    pingall                          # tester connectivité\n")
    info("    recon1 ping -c 3 gcs             # test telemetry\n")
    info("    surv2 iperf -c gcs -t 5          # test débit\n")
    info("    xterm recon1                     # ouvrir terminal sur drone\n")
    info("    py net.get('logi3').cmd('ifconfig')\n")
    info("    exit                             # quitter\n\n")

    CLI(net)
    net.stop()


def _start_realistic_traffic(net, drones, gcs, edge):
    """Lance le générateur de trafic UAV sur chaque drone."""
    import os

    # Démarre le récepteur sur la GCS
    gcs.cmd("python3 /tmp/uav_traffic_gen.py --role gcs --listen 14550 "
            "> /tmp/gcs_listener.log 2>&1 &")

    # Démarre le récepteur de stream vidéo sur l'edge server
    edge.cmd("python3 /tmp/uav_traffic_gen.py --role edge --listen 5004 "
             "> /tmp/edge_listener.log 2>&1 &")

    time.sleep(1)

    # IPs Mininet des hôtes GCS et Edge
    gcs_ip  = "10.0.0.100"
    edge_ip = "10.0.0.200"

    # Démarre l'émetteur sur chaque drone
    for dname, drone, swarm_idx, sname in drones:
        # Chaque drone envoie : telemetry @10Hz vers GCS, vidéo vers edge,
        # heartbeat @1Hz, et coordination intra-essaim
        cmd = (
            f"python3 /tmp/uav_traffic_gen.py "
            f"--role drone --name {dname} --swarm {sname} "
            f"--gcs {gcs_ip} --edge {edge_ip} "
            f"> /tmp/{dname}.log 2>&1 &"
        )
        drone.cmd(cmd)
        info(f"    ✓ Trafic démarré sur {dname}\n")

    info("*** Trafic UAV actif — voir /tmp/<drone>.log pour debug\n")


def main():
    parser = argparse.ArgumentParser(
        description="Topologie SDN UAV expert multi-essaims"
    )
    parser.add_argument("--controller", default=CONTROLLER_IP,
                        help="IP du contrôleur Ryu (défaut: 192.168.100.10 = VM1)")
    parser.add_argument("--no-mobility", action="store_true",
                        help="Désactiver la mobilité des drones")
    parser.add_argument("--no-traffic", action="store_true",
                        help="Ne pas lancer le générateur de trafic UAV")
    args = parser.parse_args()

    try:
        build_topology(args)
    except KeyboardInterrupt:
        info("\n*** Interruption — nettoyage\n")
    except Exception as e:
        warn(f"\n*** ERREUR : {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
