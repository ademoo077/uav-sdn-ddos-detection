#!/usr/bin/env bash
# =============================================================================
#  start_simulation.sh — Lanceur expert UAV-SDN DDoS Detection
# =============================================================================
#  Lance tout le stack dans une session tmux nommée "uav-sdn" :
#
#   FENÊTRE 0  : [ryu]       → Contrôleur Ryu (ryu_ml_ddos_v3.py)
#   FENÊTRE 1  : [dashboard] → Serveur Flask/SocketIO (dashboard_server_v3.py)
#   FENÊTRE 2  : [mininet]   → Topologie Mininet-WiFi (topo_expert_uav.py)
#   FENÊTRE 3  : [monitor]   → Logs temps réel (watch + tail)
#
#  Usage :
#    chmod +x start_simulation.sh
#    ./start_simulation.sh              # lancement complet
#    ./start_simulation.sh --train      # entraîner les modèles ML d'abord
#    ./start_simulation.sh --stop       # arrêter et nettoyer
#
#  Pré-requis :
#    sudo apt install tmux mininet python3-pip
#    pip install ryu flask flask-socketio eventlet python-socketio joblib
#         numpy scikit-learn xgboost tensorflow
#    (Mininet-WiFi optionnel : https://github.com/intrig-unicamp/mininet-wifi)
# =============================================================================

set -euo pipefail

# ─── COULEURS ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
SESSION="uav-sdn"
WORKDIR="$HOME/ryu_controller"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONTROLLER_IP="${CONTROLLER_IP:-192.168.100.10}"  # IP de la VM1 (Ryu)
CONTROLLER_PORT=6653
DASHBOARD_PORT=5000

# ─── FONCTIONS ───────────────────────────────────────────────────────────────
log()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()   { echo -e "${YELLOW}[⚠]${NC} $1"; }
error()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info()   { echo -e "${BLUE}[i]${NC} $1"; }
header() { echo -e "\n${CYAN}═══════════════════════════════════════════${NC}"
           echo -e "${CYAN}  $1${NC}"
           echo -e "${CYAN}═══════════════════════════════════════════${NC}\n"; }

# ─── STOP ─────────────────────────────────────────────────────────────────────
stop_all() {
    header "Arrêt de la simulation UAV-SDN"
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        tmux kill-session -t "$SESSION"
        log "Session tmux '$SESSION' terminée"
    fi
    warn "Nettoyage Mininet..."
    sudo mn --clean 2>/dev/null || true
    pkill -f "ryu_ml_ddos_v3" 2>/dev/null || true
    pkill -f "dashboard_server_v3" 2>/dev/null || true
    pkill -f "topo_expert_uav" 2>/dev/null || true
    pkill -f "uav_traffic_gen" 2>/dev/null || true
    pkill -f "hping3" 2>/dev/null || true
    pkill -f "attack_orchestrator" 2>/dev/null || true
    log "Nettoyage terminé"
    exit 0
}

# ─── VÉRIFICATION DÉPENDANCES ────────────────────────────────────────────────
check_deps() {
    header "Vérification des dépendances"
    local missing=0

    for cmd in tmux python3 mn; do
        if command -v "$cmd" &>/dev/null; then
            log "$cmd : OK"
        else
            warn "$cmd : ABSENT (peut causer des erreurs)"
            ((missing++)) || true
        fi
    done

    for pkg in ryu flask flask_socketio eventlet joblib numpy sklearn; do
        if python3 -c "import $pkg" &>/dev/null 2>&1; then
            log "python3/$pkg : OK"
        else
            warn "python3/$pkg : ABSENT"
            ((missing++)) || true
        fi
    done

    if [[ $missing -gt 0 ]]; then
        warn "$missing dépendances manquantes — la simulation peut être partielle"
    fi
}

# ─── STRUCTURE DES FICHIERS ───────────────────────────────────────────────────
setup_files() {
    header "Mise en place des fichiers"

    # Créer l'arborescence
    mkdir -p "$WORKDIR/models" "$WORKDIR/logs"
    log "Répertoires créés : $WORKDIR"

    # Copier les scripts depuis le répertoire de déploiement
    for f in topo_expert_uav.py uav_traffic_gen.py attack_orchestrator.py \
              ryu_ml_ddos_v3.py dashboard_server_v3.py dashboard.html; do
        if [[ -f "$SCRIPT_DIR/$f" ]]; then
            cp "$SCRIPT_DIR/$f" "$WORKDIR/"
            log "Copié : $f → $WORKDIR/"
        else
            warn "Fichier manquant : $SCRIPT_DIR/$f"
        fi
    done

    # Copier les scripts dans /tmp pour l'utilisation depuis Mininet
    for f in uav_traffic_gen.py attack_orchestrator.py; do
        if [[ -f "$WORKDIR/$f" ]]; then
            cp "$WORKDIR/$f" "/tmp/$f"
            chmod +x "/tmp/$f"
            log "Copié dans /tmp : $f"
        fi
    done
}

# ─── ENTRAÎNEMENT ML ──────────────────────────────────────────────────────────
train_models() {
    header "Entraînement des modèles ML"

    if [[ -f "$SCRIPT_DIR/train_model.py" ]]; then
        cp "$SCRIPT_DIR/train_model.py" "$WORKDIR/"
    fi
    if [[ -f "$SCRIPT_DIR/dataset_sdn.csv" ]]; then
        cp "$SCRIPT_DIR/dataset_sdn.csv" "$WORKDIR/"
    fi

    info "Lancement de l'entraînement (peut prendre 2-5 minutes)..."
    cd "$WORKDIR"

    if [[ -f "dataset_sdn.csv" ]]; then
        python3 train_model.py --csv dataset_sdn.csv
    else
        python3 train_model.py
    fi

    if [[ -f "models/ensemble_model.pkl" ]]; then
        log "Modèles entraînés avec succès : models/ensemble_model.pkl"
    else
        warn "Modèles non trouvés — le contrôleur utilisera le mode seuil"
    fi
}

# ─── LANCEMENT TMUX ──────────────────────────────────────────────────────────
launch_tmux() {
    header "Lancement de la session tmux '$SESSION'"

    # Tuer une session existante
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        warn "Session '$SESSION' déjà existante — suppression"
        tmux kill-session -t "$SESSION"
        sleep 1
    fi

    # ── FENÊTRE 0 : Contrôleur Ryu ──────────────────────────────────────────
    info "Démarrage du contrôleur Ryu (fenêtre 0)..."
    tmux new-session -d -s "$SESSION" -n "ryu" -x 220 -y 50

    tmux send-keys -t "$SESSION:ryu" "
echo '════════════════════════════════════════════'
echo '  FENÊTRE 0 : Contrôleur Ryu SDN + ML'
echo '  Port OpenFlow : $CONTROLLER_PORT'
echo '════════════════════════════════════════════'
cd $WORKDIR
sleep 1
ryu-manager ryu_ml_ddos_v3.py --observe-links --ofp-tcp-listen-port $CONTROLLER_PORT
" Enter

    # ── FENÊTRE 1 : Serveur Dashboard ───────────────────────────────────────
    info "Démarrage du serveur dashboard (fenêtre 1)..."
    tmux new-window -t "$SESSION" -n "dashboard"

    tmux send-keys -t "$SESSION:dashboard" "
echo '════════════════════════════════════════════'
echo '  FENÊTRE 1 : Dashboard Flask/SocketIO'
echo '  URL : http://localhost:$DASHBOARD_PORT'
echo '════════════════════════════════════════════'
cd $WORKDIR
sleep 2
python3 dashboard_server_v3.py
" Enter

    # ── FENÊTRE 2 : Topologie Mininet ───────────────────────────────────────
    info "Démarrage de la topologie Mininet (fenêtre 2)..."
    # ── FENÊTRE 2 : Topologie Mininet (à exécuter sur VM2) ──────────────────
    info "Démarrage de la topologie Mininet (fenêtre 2)..."
    tmux new-window -t "$SESSION" -n "mininet"

    tmux send-keys -t "$SESSION:mininet" "
echo '════════════════════════════════════════════════════'
echo '  FENÊTRE 2 : Topologie Mininet-WiFi'
echo '  9 drones / 3 essaims / GCS (10.0.0.100) + Edge (10.0.0.200)'
echo '  CONTROLLER : $CONTROLLER_IP (VM1)'
echo ''
echo '  ⚠ Cette fenêtre doit être exécutée sur VM2 (192.168.100.20)'
echo '  Si tu es déjà sur VM2 : appuie sur Entrée'
echo '  Sinon : ssh 192.168.100.20 puis lance :'
echo '    sudo python3 ~/ryu_controller/topo_expert_uav.py'
echo '════════════════════════════════════════════════════'
cd $WORKDIR
sleep 4
sudo python3 topo_expert_uav.py --controller $CONTROLLER_IP
" Enter

    # ── FENÊTRE 3 : Moniteur logs ────────────────────────────────────────────
    info "Démarrage du moniteur de logs (fenêtre 3)..."
    tmux new-window -t "$SESSION" -n "monitor"

    tmux send-keys -t "$SESSION:monitor" "
echo '════════════════════════════════════════════════════'
echo '  FENÊTRE 3 : Moniteur temps réel'
echo '  Dashboard : http://192.168.100.10:5000'
echo '════════════════════════════════════════════════════'
sleep 6
echo '--- Status API Dashboard ---'
watch -n 2 'echo \"=== Status Dashboard ===\" && curl -s http://192.168.100.10:5000/api/status | python3 -m json.tool 2>/dev/null || echo \"Dashboard non disponible\"'
" Enter

    log "Session tmux '$SESSION' créée avec 4 fenêtres"
}

# ─── ATTACHER LA SESSION ──────────────────────────────────────────────────────
attach_tmux() {
    header "Accès à la simulation"

    echo -e "${GREEN}"
    echo "  Session tmux : $SESSION"
    echo ""
    echo "  Architecture :"
    echo "    VM1 (192.168.100.10) → Ryu :6653 + Dashboard :5000"
    echo "    VM2 (192.168.100.20) → Mininet (9 drones)"
    echo ""
    echo "  Navigation tmux :"
    echo "    Ctrl+B puis 0   → Fenêtre Ryu (contrôleur)"
    echo "    Ctrl+B puis 1   → Fenêtre Dashboard"
    echo "    Ctrl+B puis 2   → Fenêtre Mininet (CLI)"
    echo "    Ctrl+B puis 3   → Fenêtre Moniteur"
    echo "    Ctrl+B puis d   → Détacher (laisser tourner)"
    echo ""
    echo "  Dashboard web : http://192.168.100.10:5000"
    echo "  (Accessible depuis VM1, VM2, ou tout PC sur le réseau 192.168.100.x)"
    echo ""
    echo "  Pour arrêter : ./start_simulation.sh --stop"
    echo -e "${NC}"

    sleep 2
    tmux attach-session -t "$SESSION"
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────
header "UAV-SDN DDoS Detection — Simulation Expert"
echo -e "  Contrôleur : ${CYAN}$CONTROLLER_IP:$CONTROLLER_PORT${NC}"
echo -e "  Dashboard  : ${CYAN}http://localhost:$DASHBOARD_PORT${NC}"
echo -e "  Essaims    : recon (10.0.0.11-13) | surv (10.0.0.21-23) | logi (10.0.0.31-33)"

# Traitement des arguments
TRAIN=false
for arg in "$@"; do
    case $arg in
        --stop|--clean|-s)  stop_all ;;
        --train|-t)         TRAIN=true ;;
        --check|-c)         check_deps; exit 0 ;;
        --help|-h)
            echo "Usage: $0 [--train] [--stop] [--check]"
            echo "  --train : entraîner les modèles ML avant de lancer"
            echo "  --stop  : arrêter la simulation et nettoyer"
            echo "  --check : vérifier les dépendances"
            exit 0 ;;
    esac
done

check_deps
setup_files

if $TRAIN; then
    train_models
fi

launch_tmux
attach_tmux
