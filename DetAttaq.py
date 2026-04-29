#!/usr/bin/env python3

"""
DetAttaq.py — Détecteur de bruteforce SSH basé sur les logs.
Principales fonctionnalitées :
 - Exécution continue jusqu'à interruption explicite (Ctrl+C ou fichier stop)
 - Logging structuré (console + fichier optionnel)
 - Portabilité: iptables sous Linux, netsh sous Windows (si disponible)
 - Threads propres, queue, verrouillage d'IPs
"""

import argparse
import collections
import logging
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import unicodedata
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from typing import Callable, Deque, Dict
import windows_events

# ========================
# CONFIGURATION PAR DÉFAUT
# ========================
# Définit les fichiers de log SSH pour différentes distributions Linux
# et détermine les seuils d'alerte pour la détection des bruteforces
# Dictionnaire des chemins de fichiers de log selon la distribution Linux
# Permet d'adapter le script à détecter le bon fichier de log SSH
LOG_FILES = {
    "Debian": "/var/log/auth.log",
    "Ubuntu": "/var/log/auth.log",
    "RedHat": "/var/log/secure",
    "CentOS": "/var/log/secure",
    "Arch_Linux": "/var/log/messages",
    # ⚠️ Le journal de sécurité Windows se trouve ici : r"C:\Windows\System32\winevt\Logs\Security.evtx"
    # Note : ce fichier binaire n’est pas lisible directement avec le parser de logs SSH.
    "Windows": None
}

source_win = "Detect_Attaque&Analyse_Fail" # Chemin du dossier contenant le script "DetAttaq" sur Windows

# Détection automatique de la plateforme
if sys.platform.startswith("linux"):
    DEFAULT_LOG_FILE = LOG_FILES["Debian"]
elif sys.platform.startswith("win"):
    DEFAULT_LOG_FILE = os.path.join(os.getcwd(), f"{source_win}\\api\\logs\\test_auth.log")  # fichier factice pour tests
else:
    DEFAULT_LOG_FILE = "detattaq.log"  # fallback générique


WINDOWS_SECONDS = 60      # Temps en secondes pour la fenêtre de détection des tentatives de connexion (1 min)
THRESHOLD = 5             # Nombre de tentatives d'échec de connexion avant de déclancher une alerte
CHECK_INTERVAL = 1.0      # Intervalle de lecture du fichier de log en secondes (1 s)
WHITELIST = {"127.0.0.1"} # IPs à ignorer


# Utilisé pour détecter rapidement si le seuil est atteint
failed_attempts: Dict[str, Deque[int]] = collections.defaultdict(collections.deque)

# Verrou pour sécuriser l'accès aux structures de données partagées
# Prévient les conditions de course (race conditions) entre threads
lock = threading.Lock()
blocked_ips = set()  # Pour éviter de bloquer plusieurs fois la même IP

# Expression régulière pour extraire l'adresse IP source des logs SSH
# Groupe 1: Type d'erreur ("Echec de mot de passe" ou "Failed password")
# Groupe 2: Adresse IP (4 octets séparés par des points)
IP_REGEX = re.compile(r"(Echec de mot de passe|Failed password).*from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)

# ========================
# INTERFACE FLASK
# ========================
# Configuration de l'application web pour l'interface de gestion en temps réel
app = Flask(__name__)
app.secret_key = 'detattaq_secret_key'  # Clé secrète pour les sessions Flask

# Variables globales pour gérer l'état du monitoring depuis l'interface web
monitoring_active = False  # Statut : le monitoring est-il en cours ?
monitoring_thread = None  # Référence au thread de monitoring
alerts_list = []  # Liste pour stocker les alertes (max 100)
alerts_lock = threading.Lock()  # Verrou pour l'accès thread-safe aux alertes
_stop_event = threading.Event()  # Événement pour signaler l'arrêt propre du monitoring

# ========================
# LOGGING ET ACTIONS
# ========================
logs_list = []               # Liste des actions en mémoire
logs_lock = threading.Lock() # Verrou pour accès thread-safe

def log_action(message: str, *args, level="INFO", ip=None, action=None, count=None):
    """Enregistre une action dans les logs (console + mémoire)."""
    import datetime
    if args:
        message = message % args

    # Affichage console | Sécurité : utiliser logging.info si le niveau n’existe pas
    log_func = getattr(logging, level.lower(), logging.info)
    log_func(message)

    # Stockage en mémoire pour l'interface web
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": message,
        "level": level,
        "ip": ip,
        "action": action,
        "count": count
    }
    with logs_lock:
        logs_list.append(entry)
        if len(logs_list) > 100:
            logs_list.pop(0) # Limite la taille de la liste des logs en mémoire


# ========================
# UTILITAIRES GÉNÉRAUX
# ========================
def setup_logging(logfile: str, level=logging.INFO):
    """Configure le logging console + fichier (par défaut)."""
    handlers = [logging.StreamHandler(sys.stdout)]
    # Si aucun fichier n'est fourni, utiliser un fichier par défaut dans le dossier "logs" du projet
    if not logfile:
        logfile = os.path.join(os.path.dirname(__file__), "api", "logs", "detattaq.log")

    log_dir = os.path.dirname(logfile)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True) # Créer le dossier si nécessaire
    
    handlers.append(logging.FileHandler(logfile, encoding='utf-8'))
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s", handlers=handlers)

    # Activer le level sur le logger racine
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    log_action("Configuration du logging : fichier=%s, niveau=%s", logfile, logging.getLevelName(level))
    # Application : afficher toutes les alertes et debug en mode verbose
    if level == logging.DEBUG:
        logging.debug("Mode DEBUG activé, tous les messages seront affichés.")

def is_linux() -> bool:
    """
    Détecte si le système d'exploitation est Linux.
    
    Utilité:
    - Permet d'adapter le blocage des IPs en fonction de la plateforme
    - Utilisé pour décider d'utiliser iptables (Linux) ou netsh (Windows)
    
    Returns:
        bool: True si le système est Linux, False sinon
    """
    return sys.platform.startswith("linux")

def is_windows() -> bool:
    """
    Détecte si le système d'exploitation est Windows.
    
    Utilité:
    - Permet d'adapter le blocage des IPs en fonction de la plateforme
    - Utilisé pour décider d'utiliser netsh (Windows) ou iptables (Linux)
    
    Returns:
        bool: True si le système est Windows, False sinon
    """
    return sys.platform.startswith("win")


def normalize_text(text: str) -> str:
    """
    Normalise le texte en supprimant les accents et caractères spéciaux.
    
    Utilité:
    - Prépare les lignes de log pour l'analyse par regex
    - Évite les problèmes d'encodage et de caractères accentués
    - Uniformise les formats de log pour une extraction d'IP fiable
    
    Args:
        text: Texte brut du log à normaliser
    
    Returns:
        str: Texte normalisé en ASCII
    """
    normalized = unicodedata.normalize("NFKD", text)
    stripped = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    cleaned = re.sub(r"[^\w\s\.\-:']", " ", stripped)
    return re.sub(r"\s+", " ", cleaned).strip()

# ========================
# ROUTES DE L'INTERFACE WEB
# ========================
# API REST et pages HTML pour l'interface web de gestion du détecteur
@app.route('/')
def home():
    """
    Affiche la page principale du tableau de bord web.
    
    Utilité:
    - Endpoint principal de l'interface web
    - Affiche l'état en temps réel du monitoring (actif/inactif)
    - Liste des IPs bloquées et des tentatives actuelles
    - Boutons pour démarrer/arrêter le monitoring
    
    Returns:
        render_template('home.html'): Page HTML avec le statut du système
    """
    with lock:
        status = {
            'monitoring_active': monitoring_active,
            'blocked_ips': list(blocked_ips),
            'failed_attempts': {ip: len(dq) for ip, dq in failed_attempts.items()},
            'threshold': THRESHOLD,
            'window_seconds': WINDOWS_SECONDS
        }
    return render_template('home.html', status=status)

@app.route('/api/status')
def api_status():
    """
    API REST pour obtenir l'état actuel du système en JSON.
    
    Utilité:
    - Fournit les données en JSON pour les mises à jour en temps réel du frontend
    - Retourne le statut du monitoring, IPs bloquées et tentatives actuelles
    - Utilisée par JavaScript pour rafraîchir l'interface web
    
    Returns:
        jsonify: Données JSON avec statut du système
    """
    with lock:
        data = {
            'monitoring_active': monitoring_active,
            'blocked_ips': list(blocked_ips),
            'failed_attempts': {ip: len(dq) for ip, dq in failed_attempts.items()}
        }
    return jsonify(data)


@app.route('/api/alerts')
def api_alerts():
    """
    API REST pour obtenir l'historique des alertes détectées.
    
    Utilité:
    - Fournit les alertes en JSON pour affichage temps réel sur le web
    - Permet de visualiser toutes les attaques détectées et leurs statuts
    - Les alertes sont mises à jour en temps réel sur le frontend

    """
    limit = request.args.get('limit', 50, type=int) # limit: Nombre maximum d'alertes à retourner (défaut: 50)
    with alerts_lock:
        recent_alerts = alerts_list[-limit:]
    return jsonify({'alerts': recent_alerts}) # jsonify: Liste des alertes récentes avec détails (IP, timestamp, action)


@app.route('/api/logs')
def api_logs():
    """Retourne les actions exécutées en arrière-plan."""
    limit = request.args.get("limit", 50, type=int)
    with logs_lock:
        recent_logs = logs_list[-limit:]
    return jsonify({"logs": recent_logs})


@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    """
    Démarre le monitoring en arrière-plan depuis l'interface web.
    
    Utilité:
    - Permet à l'utilisateur de lancer la surveillance via l'interface web
    - Lance un thread de monitoring en arrière-plan
    - Envoie une notification de confirmation
    
    Returns:
        redirect: Retour à la page d'accueil avec message de confirmation
    """
    global monitoring_active, monitoring_thread
    if not monitoring_active:
        # Réinitialiser l'événement d'arrêt avant de lancer le monitoring
        _stop_event.clear()
        monitoring_active = True
        monitoring_thread = threading.Thread(target=monitor_background)
        monitoring_thread.start()
        flash('Monitoring démarré.')
    else:
        flash('Monitoring déjà actif.')
    return redirect(url_for('home'))

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """
    Arrête le monitoring via l'interface web.
    
    Utilité:
    - Permet à l'utilisateur d'arrêter la surveillance
    - Signale l'événement d'arrêt aux threads de monitoring
    - Envoie une notification de confirmation
    
    Returns:
        redirect: Retour à la page d'accueil avec message de confirmation
    """
    global monitoring_active
    if monitoring_active:
        _stop_event.set()
        monitoring_active = False
        flash('Monitoring arrêté.')
    else:
        flash('Monitoring non actif.')
    return redirect(url_for('home'))


@app.route('/api/clear_alerts', methods=['POST'])
def api_clear_alerts():
    """
    API REST pour effacer l'historique des alertes.
    
    Utilité:
    - Permet à l'utilisateur de nettoyer l'historique des alertes
    - Aide à démarrer avec un historique vierge
    
    Returns:
        jsonify: Confirmation que les alertes ont été effacées
    """
    global alerts_list
    with alerts_lock:
        alerts_list = []
    return jsonify({'status': 'cleared'})

def tail_f(path: str, read_from_start: bool = False):
    """
    Émule la fonction 'tail -f' Unix : lit les nouvelles lignes du fichier en temps réel.
    
    Utilité:
    - Surveillance continue du fichier de log SSH
    - Détecte les nouvelles tentatives d'authentification au fur et à mesure
    - Mode test: peut lire depuis le début du fichier (read_from_start=True)
    
    Args:
        path: Chemin du fichier de log à surveiller
        read_from_start: Si True, lit depuis le début (pour les tests)
    
    Yields:
        str: Nouvelle ligne lue du fichier
    """
    try:
        with open(path, "r", errors="ignore") as f:
            if not read_from_start:
                # En mode normal, se positionner à la fin pour lire uniquement les nouvelles lignes
                f.seek(0, os.SEEK_END)

            while not _stop_event.is_set():
                line = f.readline()
                if not line:
                    # En mode test comme norml, attendre l'arrivée de nouvelles lignes
                    time.sleep(CHECK_INTERVAL)
                    continue
                yield line  # Emet la ligne et revient en attente sans recréer l’état de lecture.
    except FileNotFoundError:
        logging.error("Fichier de log introuvable: %s", path)
        return

# ========================
# EXTRACTION D'ADRESSES IP
# ========================
# Analyse des lignes de log pour extraire l'IP attaquante
def extract_ip(line: str):
    """
    Extrait l'adresse IP attaquante d'une ligne de log SSH.
    
    Utilité:
    - Analyse chaque ligne de log avec une regex pour trouver l'IP source
    - Supporte les formats français ("Echec de mot de passe") et anglais ("Failed password")
    - Retourne None si aucune IP n'est trouvée
    
    Args:
        line: Ligne de log brute du fichier d'authentification
    
    Returns:
        str: Adresse IP extraite ou None
    """
    normalized_line = normalize_text(line)
    match = IP_REGEX.search(normalized_line)
    if match:
        logging.debug("Ligne analysée : %s | IP extraite : %s", line.strip(), match.group(2))
        return match.group(2)
    logging.debug("Ligne analysée : %s | IP extraite : None", line.strip())
    return None

# ========================
# GESTION DES TENTATIVES ET PURGE TEMPORELLE
# ========================
# Enregistrement et nettoyage des tentatives d'authentification échouées
def record_failure(ip: str) -> int:
    """
    Enregistre une tentative échouée pour une IP et nettoie les anciennes.
    
    Utilité:
    - Ajoute le timestamp actuel à la deque de l'IP
    - Supprime les tentatives qui sortent de la fenêtre de temps (WINDOWS_SECONDS)
    - Retourne le nombre de tentatives récentes
    - Essentiels pour déterminer si le seuil d'alerte est atteint
    
    Args:
        ip: Adresse IP ayant échouée
    
    Returns:
        int: Nombre de tentatives échouées dans la fenêtre temporelle
    """
    now = int(time.time())
    cutoff = now - WINDOWS_SECONDS
    with lock:
        dq = failed_attempts[ip]
        dq.append(now)
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)
     

# ========================
# BLOCAGE CROSS-PLATEFORME DES IP
# ========================
# Implémentations spécifiques pour Linux (iptables) et Windows (netsh)
def block_ip_linux(ip: str) -> bool:
    """
    Bloque une IP attaquante en utilisant iptables sur Linux.
    
    Utilité:
    - Exécute une commande iptables pour bloquer le trafic entrant de l'IP
    - Ajoute une règle au début de la chaîne INPUT
    - Utilise le cible DROP pour rejeter les paquets
    - Nécessite des privilèges root
    
    Args:
        ip: Adresse IP à bloquer
    
    Returns:
        bool: True si le blocage réussit, False sinon
    """
    try:
        subprocess.run(["/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        logging.warning("Échec blocage iptables pour %s : %s", ip, e)
        return False

def block_ip_windows(ip: str) -> bool:
    """
    Bloque une IP attaquante en utilisant netsh sur Windows.
    
    Utilité:
    - Exécute netsh pour ajouter une règle de pare-feu
    - Bloque le trafic entrant de l'IP spécifiée
    - Nécessite des privilèges administrateur
    
    Args:
        ip: Adresse IP à bloquer
    
    Returns:
        bool: True si le blocage réussit, False sinon
    """
    try:
        # Exemple: netsh advfirewall firewall add rule name="BlockIP-<ip>" dir=in action=block remoteip=<ip>
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=BlockIP-{ip}", "dir=in", "action=block", f"remoteip={ip}"
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
        return True
    except Exception as e:
        logging.warning("Échec blocage netsh pour %s : %s", ip, e)
        return False

def alert_and_block(ip: str, count: int, allow_block: bool = True):
    """
    Gère l'alerte et le blocage automatique quand le seuil d'attaque est atteint.
    
    Utilité:
    - Enregistre l'alerte avec timestamp et détails
    - Ajoute l'alerte à la liste pour affichage en temps réel sur le web
    - Bloque l'IP via la plateforme appropriée (Linux/Windows)
    - Met à jour le statut du blocage (succès/échec)
    - Limite l'historique à 100 alertes maximum
    
    Args:
        ip: Adresse IP détectée comme attaquante
        count: Nombre de tentatives échouées durant la fenêtre
        allow_block: Si False, ne pas bloquer (mode test)
    """
    logging.debug(f"Déclenchement alerte pour IP {ip} avec {count} tentatives")
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_action("[ALERTE] L'adresse IP %s a %d échecs en %ds", ip, count, WINDOWS_SECONDS, level="WARNING", ip=ip, action="alert", count=count)
    logging.warning(alert_msg := f"ALERTE: L'IP {ip} a atteint le seuil de {count} échecs en {WINDOWS_SECONDS} secondes.")
    
    # Ajouter à la liste des alertes
    with alerts_lock:
        alerts_list.append({
            'timestamp': timestamp,
            'ip': ip,
            'count': count,
            'type': 'detection',
            'message': alert_msg,
            'blocked': False
        })
        if len(alerts_list) > 100:
            alerts_list.pop(0)
    
    if not allow_block:
        log_action(f"[ACTION] Blocage désactivé (mode test).", level="WARNING", ip=ip, action="block_attempt", count=count)
        return

    success = False
    if is_linux():
        success = block_ip_linux(ip)
    elif is_windows():
        success = block_ip_windows(ip)
    else:
        logging.warning("Plateforme non supportée pour blocage automatique.")

    if success:
        action_msg = "[ACTION] L'IP %s a été bloquée." % ip
        log_action(action_msg, level="WARNING", ip=ip, action="blocked", count=count)
        with alerts_lock:
            alerts_list[-1]['blocked'] = True
            alerts_list[-1]['action'] = 'blocked'
    else:
        warning_msg = "[ACTION] L'IP %s n'a pas pu être bloquée automatiquement." % ip
        logging.warning(warning_msg)
        with alerts_lock:
            alerts_list[-1]['action'] = 'failed'

# ========================
# THREADS DE LECTURE ET TRAITEMENT PARALLÈLE
# ========================
# Système d'architecture multi-thread avec queue pour performance optimale
def monitor_log_lines(tail_func: Callable, path: str, line_queue: queue.Queue):
    """
    Thread lecteur: récupère les lignes du log et les place dans la queue.
    
    Utilité:
    - Fonctionne en parallèle pour lire les logs sans bloquer le traitement
    - Utilise tail_f pour l'émulation de 'tail -f'
    - Envoie les lignes à une queue thread-safe pour traitement par les workers
    - S'arrête proprement quand _stop_event est signalé
    """
    for line in tail_func(path):
        if _stop_event.is_set():
            break
        try:
            line_queue.put(line, timeout=1)
        except queue.Full:
            logging.warning("File de lignes pleine, ligne perdue.")

def process_log_lines(line_queue: queue.Queue, allow_block: bool):
    """
    Thread worker: traite les lignes de log pour détecter les attaques.
    
    Utilité:
    - Récupère les lignes de la queue thread-safe
    - Extrait l'IP attaquante de chaque ligne
    - Filtre les IPs whitelistées
    - Enregistre les tentatives échouées
    - Lance une alerte + blocage si le seuil est atteint
    - Évite les doublons grâce à blocked_ips
    
    Args:
        line_queue: Queue contenant les lignes à traiter
        allow_block: Si False, ne pas bloquer automatiquement (mode test)
    """
    while not _stop_event.is_set():
        try:
            line = line_queue.get(timeout=1)
        except queue.Empty:
            continue
        if line is None:
            break
        ip = extract_ip(line)
        if not ip or ip in WHITELIST:
            line_queue.task_done()
            continue
        logging.debug(f"Tentative échouée détectée depuis IP: {ip}")
        with lock:
            if ip in blocked_ips:
                line_queue.task_done()
                continue
        count = record_failure(ip)
        logging.debug(f"IP {ip} a maintenant {count} tentatives échouées")
        if count >= THRESHOLD:
            with lock:
                if ip in blocked_ips:
                    line_queue.task_done()
                    continue
                blocked_ips.add(ip)
                failed_attempts[ip].clear()
            alert_and_block(ip, count, allow_block)
        line_queue.task_done()

# ========================
# GESTION DES SIGNAUX ET ARRÊT PROPRE
# ========================
# Permet d'arrêter le service de manière propre via Ctrl+C ou signal SIGTERM
def _signal_handler(signum, frame):
    """
    Gestionnaire de signaux Unix (SIGINT, SIGTERM).
    
    Utilité:
    - Permet d'arrêter proprement le service avec Ctrl+C ou kill
    - Signale l'arrêt à tous les threads
    - Enregistre l'arrêt dans les logs
    
    Args:
        signum: Numéro du signal reçu
        frame: Frame de la pile d'appels
    """
    log_action(f"Signal reçu (%s). Arrêt demandé.", signal.Signals(signum).name, level="INFO", action="signal_stop")
    _stop_event.set()

# Enregistre les gestionnaires de signaux pour permettre un arrêt propre
signal.signal(signal.SIGINT, _signal_handler)  # Ctrl+C
if hasattr(signal, "SIGTERM"):  # Peut ne pas exister sous Windows
    signal.signal(signal.SIGTERM, _signal_handler)  # Arrêt via signal

# ========================
# FONCTION DE LECTURE DE LOG
# ========================
# Implémentation de la surveillance continue du fichier de log
def monitor_background(log_file=DEFAULT_LOG_FILE, worker_count=2, allow_block=True, logfile=None, stop_file=None, read_from_start=False, windows_events_enabled=False):
    """
    Lance le monitoring en arrière-plan depuis l'interface web.
    
    Utilité:
    - Enveloppe pour la fonction monitor() utilisée par les threads web
    - Permet de démarrer/arrêter le monitoring via l'interface Flask
    """
    monitor(log_file=log_file, worker_count=worker_count, allow_block=allow_block, logfile=logfile, stop_file=stop_file, read_from_start=read_from_start, windows_events_enabled=windows_events_enabled)

def monitor(log_file=DEFAULT_LOG_FILE, worker_count=2, allow_block=True, logfile=None, stop_file=None, tail_func=None, read_from_start=False, windows_events_enabled=False):
    """
    Fonction principale de monitoring : orchestre la surveillance en temps réel.
    
    Utilité:
    - Crée et gère les threads de lecture et traitement en parallèle
    - Utilise une queue thread-safe pour la communication entre threads
    - Boucle principale jusqu'à arrêt explicite (signal, fichier stop, ou web)
    - Effectue un arrêt propre de tous les threads
    
    Args:
        log_file: Chemin du fichier de log à surveiller
        worker_count: Nombre de threads workers pour traiter les logs
        allow_block: Si False, alerte sans bloquer (mode test)
        logfile: Fichier optionnel pour enregistrer les logs
        stop_file: Fichier sentinel (si créé, déclenche l'arrêt)
        tail_func: Fonction personnalisée pour lire les logs (pour les tests)
        read_from_start: Si True, lit le fichier depuis le début
        windows_events_enabled: Si True, active la surveillance des événements Windows
    """
    if tail_func is None:
        tail_func = lambda path: tail_f(path, read_from_start)
    line_queue = queue.Queue(maxsize=1000)
    
    # Thread lecteur Linux
    reader = threading.Thread(target=monitor_log_lines, args=(tail_func, log_file, line_queue), daemon=True)
    reader.start()
    
    # Thread lecteur Windows si activé
    windows_reader = None
    if is_windows() and windows_events_enabled:
        windows_reader = threading.Thread(target=windows_events.read_windows_events, args=(line_queue, read_from_start), daemon=True)
        windows_reader.start()
        log_action("Surveillance des événements Windows activée.", level="INFO", action="windows_events_start")
    
    workers = []
    for _ in range(worker_count):
        w = threading.Thread(target=process_log_lines, args=(line_queue, allow_block), daemon=True)
        w.start()
        workers.append(w)
    log_action(f"Démarrage du détecteur sur %s (workers=%d).", log_file, worker_count, level="INFO", action="monitor_start")

    try:
        while not _stop_event.is_set():
            if stop_file and os.path.exists(stop_file):
                log_action(f"Fichier stop détecté (%s). Arrêt demandé.", stop_file, level="INFO", action="file_stop")
                _stop_event.set()
                break
            time.sleep(1)
    except KeyboardInterrupt:
        log_action(f"Interruption clavier reçue. Arrêt en cours...", level="INFO", action="keyboard_interrupt")
        _stop_event.set()
    finally:
        # Arrêt propre: vider la queue et signaler les workers
        for _ in workers:
                line_queue.put(None, timeout=1)
        for w in workers:
            w.join(timeout=2)
        log_action(f"Ferméture du service... Workers stoppés.", level="INFO", action="monitor_stop")

# ========================
# INTERFACE LIGNE DE COMMANDE (CLI)
# ========================
# Parse les arguments et détermine le mode d'exécution
def main():
    """
    Point d'entrée principal du script DetAttaq.
    
    Utilité:
    - Parse les arguments de ligne de commande
    - Configure le logging
    - Décide entre mode web (interface Flask) ou mode CLI (monitoring direct)
    - Vérifie la compatibilité de la plateforme
    - Lance le service approprié
    """
    parser = argparse.ArgumentParser(description="Détecteur de bruteforce SSH basé sur les logs.")
    parser.add_argument("--log-file", default=DEFAULT_LOG_FILE, help="Chemin du fichier de log à surveiller.")
    parser.add_argument("--workers", type=int, default=2, help="Nombre de threads de traitement.")
    parser.add_argument("--no-block", action="store_true", help="Ne pas tenter de bloquer les IP (mode test).")
    parser.add_argument("--log-output", help="Fichier de log local pour enregistrer les événements.")
    parser.add_argument("--stop-file", help="Chemin d'un fichier sentinel: si présent, le script s'arrête proprement.")
    parser.add_argument("--ignore-platform-check", action="store_true", help="Ignorer la vérification de la plateforme.")
    parser.add_argument("--web", action="store_true", help="Lancer l'interface web Flask.")
    parser.add_argument("--read-from-start", action="store_true", help="Lire le fichier de log depuis le début (pour les tests).")
    parser.add_argument("--verbose", action="store_true", help="Activer le mode verbose avec plus de détails de débogage.")
    parser.add_argument("--windows-events", choices=["enable", "disable", "auto"], default="auto", help="Contrôler la surveillance des événements Windows (auto=activé sur Windows).")
    args = parser.parse_args()

    # Configuration du logging selon les arguments
    setup_logging(
        args.log_output, level=logging.DEBUG 
        if args.verbose 
        else logging.INFO
    )

    # Déterminer si activer les événements Windows
    if args.windows_events == "enable":
        windows_events_enabled = True
    elif args.windows_events == "disable":
        windows_events_enabled = False
    else:  # auto
        windows_events_enabled = is_windows()

    if args.web:
        log_action(f"Lancement de l'interface web sur http://localhost:5000", level="INFO", action="web_start")
        # Démarrage automatique du monitoring en mode web
        _stop_event.clear()
        monitoring_thread = threading.Thread(
            target=monitor_background,
            kwargs={
                'log_file': args.log_file,
                'worker_count': args.workers,
                'allow_block': not args.no_block,
                'logfile': args.log_output,
                'stop_file': args.stop_file,
                'read_from_start': args.read_from_start,
                'windows_events_enabled': windows_events_enabled,
            },
            daemon=True,
        )
        monitoring_thread.start()
        app.run(debug=False, host='0.0.0.0', port=5000)
    else:
        if not args.ignore_platform_check and not (is_linux() or is_windows()):
            logging.error("Plateforme non supportée par défaut. Utilisez --ignore-platform-check pour forcer.")
            sys.exit(1)

        allow_block = not args.no_block
        read_from_start = args.read_from_start
        if not args.read_from_start and os.path.exists(args.log_file) and os.path.getsize(args.log_file) > 0:
            log_action(f"Fichier de log existant détecté (%s), lecture depuis le début en mode test.", args.log_file, level="INFO", action="test_mode_auto")
            read_from_start = True

        # Démarrage du monitoring
        monitor(log_file=args.log_file, worker_count=args.workers, allow_block=allow_block, logfile=args.log_output, stop_file=args.stop_file, read_from_start=read_from_start, windows_events_enabled=windows_events_enabled)

if __name__ == "__main__":
    # Point d'entrée du script Python - exécute main() si le fichier est run directement
    main()
