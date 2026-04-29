#!/usr/bin/env python3
"""
simulate_logs.py — Générateur de faux logs SSH pour tester DetAttaq.py
- Génère des tentatives aléatoires depuis plusieurs IPs
- Envoie parfois des rafales d'échecs pour déclencher des alertes
"""

import os
import time
import random

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "api", "logs")
LOG_FILE = os.path.join(LOG_DIR, "test_auth.log")  # Fichier de log factice
IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "203.0.113.42"]

MESSAGES = [
    "Failed password for root from {ip} port 22 ssh2",
    "Echec de mot de passe pour admin depuis {ip} port 22 ssh2"
]

def generate_logs():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        while True:
            ip = random.choice(IPS)

            # 1 chance sur 5 de générer une rafale d'échecs
            if random.randint(1, 5) == 5:
                print(f"[SIMULATION] Rafale d'échecs pour {ip}")
                for _ in range(random.randint(5, 10)):  # rafale de 5 à 10 tentatives
                    msg = random.choice(MESSAGES).format(ip=ip)
                    f.write(msg + "\n")
                    f.flush()
                    print(f"  -> {msg}")
                    time.sleep(0.2)  # intervalle court pour simuler attaque brute-force
            else:
                # Tentative normale
                msg = random.choice(MESSAGES).format(ip=ip)
                f.write(msg + "\n")
                f.flush()
                print(f"[SIMULATION] Ajouté: {msg}")
                time.sleep(random.uniform(0.5, 2.0))  # intervalle aléatoire

if __name__ == "__main__":
    print(f"Simulation en cours, écriture dans {LOG_FILE}...")
    generate_logs()
