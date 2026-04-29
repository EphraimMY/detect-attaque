from flask import Flask, jsonify, render_template, request
import threading
import datetime

app = Flask(__name__)

# Mémoire pour stocker les logs et alertes
logs = []
logs_list = [] # liste des actions en mémoire
logs_lock = threading.Lock() # verrou pour accès thread-safe
alerts = []
blocked_ips = set()
failed_attempts = {}

def log_action(message, level="INFO", ip=None, action=None, count=None):
    entry = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "message": message,
        "level": level,
        "ip": ip,
        "action": action,
        "count": count
    }
    with logs_lock:
        if len(logs_list) > 100:
            logs_list.pop(0) # limiter la taille de la liste des logs

@app.route("/")
def index():
    # rend la page HTML (ton template)
    return render_template("index.html", status={
        "threshold": 5,
        "window_seconds": 60
    })

@app.route("/api/status")
def api_status():
    return jsonify({
        "monitoring_active": True,  # à adapter selon ton script
        "threshold": 5,
        "window_seconds": 60,
        "blocked_ips": list(blocked_ips),
        "failed_attempts": failed_attempts
    })

@app.route("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 50))
    return jsonify({"alerts": alerts[-limit:]})

@app.route('/api/logs')
def api_logs():
    """
    API REST pour obtenir les actions exécutées en arrière-plan.
    
    Returns:
        jsonify: Liste des logs récents
    """
    limit = request.args.get("limit", 50, type=int)
    with logs_lock:
        recent_logs = logs_list[-limit:]
    return jsonify({"logs": recent_logs})

@app.route("/api/clear_alerts", methods=["POST"])
def clear_alerts():
    alerts.clear()
    return jsonify({"status": "ok"})
