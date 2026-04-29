# windows_events.py
"""
Module pour la surveillance des événements Windows Event Log (Security.evtx).
Fournit des fonctions pour lire, parser et intégrer les événements d'échec de logon.
"""

import os
import subprocess
import time
import logging
import re
from typing import Optional

# Configuration pour les événements Windows
WINDOWS_EVENTS_TIMESTAMP_FILE = os.path.join(os.path.dirname(__file__), "api", "logs", ".windows_events_timestamp")
EVENT_ID_LOGON_FAILURE = 4625

def get_last_windows_event_timestamp() -> Optional[str]:
    """
    Récupère le timestamp du dernier événement traité depuis le fichier de sauvegarde.

    Returns:
        str: Timestamp ISO du dernier événement traité, ou None si fichier absent
    """
    if os.path.exists(WINDOWS_EVENTS_TIMESTAMP_FILE):
        try:
            with open(WINDOWS_EVENTS_TIMESTAMP_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception as e:
            logging.warning(f"Erreur lecture timestamp Windows Events: {e}")
    return None

def save_last_windows_event_timestamp(timestamp: str):
    """
    Sauvegarde le timestamp du dernier événement traité.

    Args:
        timestamp: Timestamp ISO à sauvegarder
    """
    try:
        os.makedirs(os.path.dirname(WINDOWS_EVENTS_TIMESTAMP_FILE), exist_ok=True)
        with open(WINDOWS_EVENTS_TIMESTAMP_FILE, "w", encoding="utf-8") as f:
            f.write(timestamp)
    except Exception as e:
        logging.warning(f"Erreur sauvegarde timestamp Windows Events: {e}")

def extract_ip_from_windows_event(event_text: str) -> Optional[str]:
    """
    Extrait l'adresse IP source d'un événement Windows Event Log formaté en texte.

    Args:
        event_text: Texte brut de l'événement wevtutil

    Returns:
        str: Adresse IP extraite, ou None si non trouvée
    """
    # Recherche du champ IpAddress dans le format wevtutil
    ip_match = re.search(r"IpAddress:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", event_text, re.IGNORECASE)
    if ip_match:
        ip = ip_match.group(1).strip()
        # Vérifier que c'est une IP valide (pas vide, pas locale)
        if ip and ip not in ("-", "127.0.0.1", "::1", ""):
            return ip
    return None

def format_windows_event_for_log(event_text: str) -> str:
    """
    Formate un événement Windows pour qu'il soit traité comme une ligne de log standard.

    Args:
        event_text: Texte brut de l'événement

    Returns:
        str: Ligne formatée compatible avec IP_REGEX
    """
    ip = extract_ip_from_windows_event(event_text)
    if ip:
        return f"Failed password for invalid user from {ip} port 0 ssh2 [Event ID {EVENT_ID_LOGON_FAILURE}]"
    return ""

def read_windows_events(line_queue, read_from_start: bool = False):
    """
    Thread lecteur pour surveiller les événements Windows Event Log.

    Args:
        line_queue: Queue pour envoyer les lignes formatées
        read_from_start: Si True, lit tous les événements disponibles
    """
    logging.info("Démarrage surveillance Windows Event Log")

    last_timestamp = None if read_from_start else get_last_windows_event_timestamp()

    while True:
        try:
            # Construire la commande wevtutil
            cmd = ["wevtutil", "qe", "Security", "/f:text", f"/q:*[System[(EventID={EVENT_ID_LOGON_FAILURE})]]", "/c:100", "/rd:true"]
            if last_timestamp:
                # Note: wevtutil ne supporte pas facilement le filtrage par timestamp, on utilise une approche simple
                pass

            # Exécuter wevtutil
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )

            if result.returncode != 0:
                logging.warning(f"Erreur wevtutil: {result.stderr.strip()}")
                if "Access is denied" in result.stderr or "Accès refusé" in result.stderr:
                    logging.error("Accès refusé au journal Security. Nécessite privilèges administrateur.")
                time.sleep(10)
                continue

            output = result.stdout
            if not output.strip():
                time.sleep(5)
                continue

            # Traiter chaque ligne
            for line in output.splitlines():
                if "IpAddress:" in line:
                    formatted_line = format_windows_event_for_log(line)
                    if formatted_line:
                        try:
                            line_queue.put(formatted_line, timeout=1)
                            logging.debug(f"Événement Windows ajouté à la queue: {formatted_line}")
                        except Exception as e:
                            logging.warning(f"Erreur ajout à queue: {e}")

            # Sauvegarder un timestamp approximatif (dernier événement traité)
            # Pour simplifier, on ne gère pas les timestamps ici
            time.sleep(5)

        except subprocess.TimeoutExpired:
            logging.warning("Timeout wevtutil, retry dans 10s")
            time.sleep(10)
        except Exception as e:
            logging.error(f"Erreur surveillance Windows Events: {e}")
            time.sleep(10)