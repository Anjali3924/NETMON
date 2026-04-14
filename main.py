import os
import time
import subprocess
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, deque
from functools import wraps

import numpy as np

#  IP GEO DETAILS (ONLINE API)
import ipaddress
from cachetools import TTLCache
import requests

from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, jsonify, render_template, request,
    send_from_directory,
    session, redirect, url_for
)

from db import init_db, insert_inventory_run, get_history_summary
from auth_db import init_auth_db, create_user, get_user_by_email


# =========================
# PATHS
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
SEC_DB_PATH = os.path.join(BASE_DIR, "netmon_security.db")


# =========================
# GLOBAL SETTINGS
# =========================
TSHARK_PATH = None if os.environ.get("RENDER") else r"C:\Program Files\Wireshark\tshark.exe" # Render / Linux
INTERFACE_NO = "Wi-Fi"   # change if your interface name differs
PROC_TIMEOUT = 12


# =========================
# FLASK APP
# =========================
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

#  Better: take secret from env if available
app.secret_key = os.environ.get("NETMON_SECRET_KEY", "netmon_secret_key_change_this")

#  DEV SETTINGS
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

#  Basic session hardening (safe for dev too)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = not app.debug


# =========================
# INIT DATABASES
# =========================
init_db()
init_auth_db()


# =========================
# LOGIN REQUIRED DECORATOR
# =========================
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_email"):
            return redirect(url_for("login_page"))
        return fn(*args, **kwargs)
    return wrapper


# =========================
# GLOBAL LOCK (block all pages before login)
# Only HOME is allowed + auth endpoints + favicon + live_stats
# =========================
PUBLIC_ENDPOINTS = {
    "home",
    "login_page",
    "register_user",
    "favicon",
    "auth_google",
    "api_live_stats",
    "static",
}

@app.before_request
def enforce_login_everywhere():
    endpoint = request.endpoint
    if endpoint is None:
        return None

    # allow public endpoints
    if endpoint in PUBLIC_ENDPOINTS:
        return None

    # allow static files
    if endpoint.startswith("static"):
        return None

    # block everything else
    if not session.get("user_email"):
        return redirect(url_for("login_page"))

    return None


@app.after_request
def add_no_cache_headers(resp):
    if app.debug:
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


# =========================
# SECURITY DB HELPERS
# =========================
def get_sec_db():
    conn = sqlite3.connect(SEC_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_security_db():
    conn = get_sec_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            total INTEGER,
            normal INTEGER,
            suspicious INTEGER,
            status TEXT,
            severity TEXT,
            threshold INTEGER
        )
    """)

    #  Safe migration: add columns if missing
    for sql in [
        "ALTER TABLE security_scans ADD COLUMN top_ip TEXT",
        "ALTER TABLE security_scans ADD COLUMN top_ip_count INTEGER",
        "ALTER TABLE security_scans ADD COLUMN top_talker_ip TEXT",
        "ALTER TABLE security_scans ADD COLUMN top_talker_count INTEGER",
        "ALTER TABLE security_scans ADD COLUMN threshold_value INTEGER",
        "ALTER TABLE security_scans ADD COLUMN threshold_base INTEGER",
    ]:
        try:
            cur.execute(sql)
        except Exception:
            pass

    conn.commit()
    conn.close()


def insert_security_scan(
    ts,
    total,
    normal,
    suspicious,
    status,
    severity,
    threshold_base,
    threshold_value,
    top_ip=None,
    top_ip_count=0,
    top_talker_ip=None,
    top_talker_count=0
):
    conn = get_sec_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO security_scans (
            ts, total, normal, suspicious, status, severity, threshold,
            top_ip, top_ip_count,
            top_talker_ip, top_talker_count,
            threshold_value, threshold_base
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ts, total, normal, suspicious, status, severity,
        int(threshold_base or 0),
        top_ip, int(top_ip_count or 0),
        top_talker_ip, int(top_talker_count or 0),
        int(threshold_value or 0),
        int(threshold_base or 0)
    ))

    conn.commit()
    conn.close()


def fetch_security_history(days: int = 2):
    cutoff = datetime.now() - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_sec_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            ts, total, normal, suspicious, status, severity, threshold,
            top_ip, top_ip_count,
            top_talker_ip, top_talker_count,
            threshold_value, threshold_base
        FROM security_scans
        WHERE ts >= ?
        ORDER BY ts DESC
    """, (cutoff_str,))
    rows = cur.fetchall()
    conn.close()

    scans = []
    for r in rows:
        display_ip = r["top_ip"] if r["top_ip"] else r["top_talker_ip"]
        display_count = r["top_ip_count"] if r["top_ip"] else r["top_talker_count"]

        scans.append({
            "ts": r["ts"],
            "total": r["total"],
            "normal": r["normal"],
            "suspicious": r["suspicious"],
            "status": r["status"],
            "severity": r["severity"],

            "threshold_base": r["threshold_base"] if r["threshold_base"] is not None else r["threshold"],
            "threshold_value": r["threshold_value"],

            "top_ip": display_ip,
            "top_ip_count": int(display_count or 0),

            "top_talker_ip": r["top_talker_ip"],
            "top_talker_count": r["top_talker_count"],
        })

    return {
        "days": days,
        "from": cutoff_str,
        "total_scans": len(scans),
        "scans": scans
    }


init_security_db()


# =========================
# IP DETAILS (ONLINE LOOKUP)
# =========================
IP_DETAILS_CACHE = TTLCache(maxsize=5000, ttl=60 * 60)

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def rfc1918_range(ip: str) -> str:
    if ":" in ip:
        return "N/A (IPv6)"
    if ip.startswith("10."):
        return "10.0.0.0/8"
    if ip.startswith("192.168."):
        return "192.168.0.0/16"
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return "172.16.0.0/12"
        except Exception:
            pass
    return "-"

def ip_flags(ip: str) -> dict:
    a = ipaddress.ip_address(ip)
    return {
        "ip_version": "IPv6" if a.version == 6 else "IPv4",
        "rfc1918_range": rfc1918_range(ip),
        "is_private": bool(a.is_private),
        "is_loopback": bool(a.is_loopback),
        "is_link_local": bool(a.is_link_local),
        "is_multicast": bool(a.is_multicast),
        "is_reserved": bool(a.is_reserved),
        "is_unspecified": bool(a.is_unspecified),
    }

@app.get("/api/ip-details")
@login_required
def api_ip_details():
    ip = (request.args.get("ip") or "").strip()

    if not validate_ip(ip):
        return jsonify({"ok": False, "error": "Invalid IP address"}), 400

    if ip in IP_DETAILS_CACHE:
        return jsonify({"ok": True, "ip": ip, **IP_DETAILS_CACHE[ip]}), 200

    # PRIVATE / INTERNAL
    if not is_public_ip(ip):
        data = {
            "type": "private",
            "note": "Private/internal IP. Geo-location is not applicable.",
            **ip_flags(ip)
        }
        IP_DETAILS_CACHE[ip] = data
        return jsonify({"ok": True, "ip": ip, **data}), 200

    # PUBLIC
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,regionName,isp,org,lat,lon,timezone,query"
        r = requests.get(url, timeout=6, headers={"User-Agent": "NetMon/1.0"})
        j = r.json()

        if j.get("status") != "success":
            return jsonify({"ok": False, "error": j.get("message", "IP lookup failed")}), 500

        data = {
            "type": "public",
            "country": j.get("country"),
            "city": j.get("city"),
            "region": j.get("regionName"),
            "isp": j.get("isp"),
            "org": j.get("org"),
            "latitude": j.get("lat"),
            "longitude": j.get("lon"),
            "timezone": j.get("timezone"),
        }

        IP_DETAILS_CACHE[ip] = data
        return jsonify({"ok": True, "ip": ip, **data}), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# =========================
# FAVICON
# =========================
@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.static_folder, "images"),
        "favicon.png",
        mimetype="image/png"
    )


# =========================
# TSHARK HELPER
# =========================
def run_tshark(command):

    # 🚀 SIMULATION MODE (for Render / Linux)
    if not TSHARK_PATH or TSHARK_PATH is None:
        fake_output = []
        for i in range(10):
            fake_output.append(
                f"{i}|192.168.1.{i + 2}|8.8.8.8|{64 + i *300 }"
            )
        return "\n".join(fake_output), None

    # 💻 LOCAL MODE (your laptop)
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            out, err = process.communicate(timeout=PROC_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            return None, "tshark timeout"

        out = (out or "").strip()
        err = (err or "").strip()

        if out:
            return out, None

        return None, "No packets captured"

    except FileNotFoundError:
        return None, "tshark not found"
    except Exception as e:
        return None, str(e)



# =========================
# INTERNAL HELPERS
# =========================
def classify_ip(ip: str) -> str:
    if ip.startswith("10.") or ip.startswith("192.168."):
        return "Internal"
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return "Internal"
        except Exception:
            pass
    return "External"


def capture_inventory_devices(duration_sec: int = 4, cap: int = 30):
    command = [
         None, "-i", INTERFACE_NO, "-n",
        "-a", f"duration:{duration_sec}",
        "-c", str(cap),
        "-Y", "ip",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-E", "separator=|"
    ]

    output, error = run_tshark(command)
    if output is None:
        return None, error

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    device_map = {}
    packet_count = defaultdict(int)

    for line in output.splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2:
            continue

        src, dst = parts[0], parts[1]
        for ip in (src, dst):
            if not ip or ip == "-" or ip.lower() == "unknown":
                continue

            packet_count[ip] += 1

            if ip not in device_map:
                device_map[ip] = {
                    "ip": ip,
                    "type": classify_ip(ip),
                    "packets": 0,
                    "first_seen": now,
                    "last_seen": now
                }

            device_map[ip]["last_seen"] = now
            device_map[ip]["packets"] = packet_count[ip]

    devices = list(device_map.values())
    devices.sort(key=lambda x: x["packets"], reverse=True)

    internal = sum(1 for d in devices if d["type"] == "Internal")
    external = sum(1 for d in devices if d["type"] == "External")

    return {
        "total": len(devices),
        "internal": internal,
        "external": external,
        "devices": devices
    }, None


# =========================
# SECURITY SCAN (FIXED)
# - threshold_base = 1200 (config)
# - threshold_value = MAX packet length seen in scan
# - LOW / MEDIUM / HIGH:
#     LOW    : max_len < 0.90*T
#     MEDIUM : 0.90*T <= max_len <= T
#     HIGH   : max_len > T  (SUSPICIOUS)
# =========================
def capture_security_scan(duration_sec: int = 3, cap: int = 40, length_threshold: int = 1200):
    command = [
        TSHARK_PATH, "-i", INTERFACE_NO, "-n",
        "-a", f"duration:{duration_sec}",
        "-c", str(cap),
        "-Y", "ip",
        "-T", "fields",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-E", "separator=|"
    ]

    output, error = run_tshark(command)
    if output is None:
        return None, error

    total = 0
    suspicious = 0
    max_len = 0

    susp_ip_counts = defaultdict(int)
    talker_counts = defaultdict(int)

    for line in output.splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue

        frame_len, src, dst = parts[0], parts[1], parts[2]
        if not str(frame_len).isdigit():
            continue

        l = int(frame_len)
        total += 1
        if l > max_len:
            max_len = l

        if src and src != "-" and src.lower() != "unknown":
            talker_counts[src] += 1
        if dst and dst != "-" and dst.lower() != "unknown":
            talker_counts[dst] += 1

        if l > length_threshold:
            suspicious += 1
            if src and src != "-" and src.lower() != "unknown":
                susp_ip_counts[src] += 1
            if dst and dst != "-" and dst.lower() != "unknown":
                susp_ip_counts[dst] += 1

    if total == 0:
        return None, "No valid packets captured (try generating traffic and run again)."

    normal = total - suspicious

    top_ip = None
    top_ip_count = 0
    if susp_ip_counts:
        top_ip, top_ip_count = max(susp_ip_counts.items(), key=lambda x: x[1])

    top_talker_ip = None
    top_talker_count = 0
    if talker_counts:
        top_talker_ip, top_talker_count = max(talker_counts.items(), key=lambda x: x[1])

    T = int(length_threshold or 1200)
    medium_floor = int(0.90 * T)

    if max_len > T:
        severity = "HIGH"
        status = "SUSPICIOUS"
    elif max_len >= medium_floor:
        severity = "MEDIUM"
        status = "SAFE"
    else:
        severity = "LOW"
        status = "SAFE"

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    insert_security_scan(
        ts=ts,
        total=total,
        normal=normal,
        suspicious=suspicious,
        status=status,
        severity=severity,
        threshold_base=T,
        threshold_value=max_len,
        top_ip=top_ip,
        top_ip_count=int(top_ip_count or 0),
        top_talker_ip=top_talker_ip,
        top_talker_count=int(top_talker_count or 0),
    )

    return {
        "ts": ts,
        "total": total,
        "normal": normal,
        "suspicious": suspicious,
        "status": status,
        "severity": severity,
        "threshold_base": T,
        "threshold_value": max_len,

        "severity_rules": {
            "low_max": medium_floor - 1,
            "medium_min": medium_floor,
            "medium_max": T,
            "high_min": T + 1
        },

        "top_ip": top_ip,
        "top_ip_count": int(top_ip_count or 0),
        "top_talker_ip": top_talker_ip,
        "top_talker_count": int(top_talker_count or 0),
    }, None


# =========================
# LIVE STATS (HOME)
# =========================
PPS_WINDOW = deque(maxlen=60)

LAST_LIVE_STATS = {
    "ok": True,
    "ts": int(time.time()),
    "pps": 0,
    "tps": 0,
    "active_flows": 0,
    "avg_len": 0,
    "anom": False,
    "z": 0.0,
    "baseline_pps": None,
    "threat_level": "NORMAL",
    "threat_score": 0,
    "ai_reasons": ["Waiting for traffic…"],
    "protocols": {}
}


def capture_live_traffic(duration_sec: int = 1, cap: int = 250, length_threshold: int = 1200):
    command = [
        TSHARK_PATH, "-i", INTERFACE_NO, "-n",
        "-a", f"duration:{duration_sec}",
        "-c", str(cap),
        "-Y", "ip",
        "-T", "fields",
        "-e", "_ws.col.Protocol",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-E", "separator=|"
    ]

    out, err = run_tshark(command)
    if out is None:
        return None, err

    protocols = defaultdict(int)
    lengths = []
    flows = set()
    big = 0

    for line in out.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            continue

        proto = parts[0] or "UNKNOWN"
        protocols[proto] += 1

        if parts[1].isdigit():
            l = int(parts[1])
            lengths.append(l)
            if l > length_threshold:
                big += 1

        src = parts[2] or ""
        dst = parts[3] or ""
        if src and dst:
            flows.add((src, dst))

    total = len(lengths)
    if total == 0:
        return None, "No packets captured. Generate traffic (YouTube / speedtest) and try again."

    avg_len = int(sum(lengths) / total) if total else 0
    pps = int(total / max(1, duration_sec))
    tps = int(big / max(1, duration_sec))
    active_flows = len(flows)

    return {
        "pps": pps,
        "tps": tps,
        "active_flows": active_flows,
        "avg_len": avg_len,
        "protocols": dict(protocols)
    }, None


def compute_threat_and_reasons(pps, tps, avg_len, z, is_anom):
    score = 0
    reasons = []

    if is_anom:
        score += 35
        reasons.append(f"Traffic spike detected (z={round(z, 2)}).")
    else:
        reasons.append("No strong risk signals detected.")

    if tps >= 5:
        score += 35
        reasons.append(f"High suspicious packet rate (threats/sec={tps}).")
    elif tps >= 2:
        score += 18
        reasons.append(f"Moderate suspicious packets (threats/sec={tps}).")

    if avg_len >= 900:
        score += 18
        reasons.append(f"High average packet size ({avg_len} bytes).")
    elif avg_len >= 600:
        score += 10
        reasons.append(f"Moderate average packet size ({avg_len} bytes).")

    score = max(0, min(100, score))

    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "SUSPICIOUS"
    else:
        level = "NORMAL"

    return level, int(score), reasons[:5]


@app.route("/api/live_stats")
def api_live_stats():
    payload, error = capture_live_traffic(duration_sec=1, cap=250, length_threshold=1200)

    if payload is None:
        cached = dict(LAST_LIVE_STATS)
        cached["ok"] = False
        cached["error"] = error
        cached["ts"] = int(time.time())
        return jsonify(cached), 200

    pps = payload["pps"]
    PPS_WINDOW.append(pps)

    baseline = None
    z = 0.0
    is_anom = False

    if len(PPS_WINDOW) >= 15:
        arr = np.array(PPS_WINDOW, dtype=float)
        mean = float(arr.mean())
        std = float(arr.std())
        baseline = round(mean, 2)

        if std > 1e-6:
            z = (pps - mean) / std
            is_anom = (z >= 2.2)

    level, score, reasons = compute_threat_and_reasons(
        pps=payload["pps"],
        tps=payload["tps"],
        avg_len=payload["avg_len"],
        z=z,
        is_anom=is_anom
    )

    resp = {
        "ok": True,
        "ts": int(time.time()),
        "pps": payload["pps"],
        "tps": payload["tps"],
        "active_flows": payload["active_flows"],
        "avg_len": payload["avg_len"],
        "anom": bool(is_anom),
        "z": round(float(z), 2),
        "baseline_pps": baseline,
        "threat_level": level,
        "threat_score": int(score),
        "ai_reasons": reasons,
        "protocols": payload["protocols"]
    }

    LAST_LIVE_STATS.update(resp)
    return jsonify(resp), 200


# =========================
# GOOGLE (DEMO)
# =========================
@app.route("/auth/google")
def auth_google():
    return redirect(url_for("login_page", google="demo"))


# =========================
# AUTH ROUTES (PUBLIC)
# =========================
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        google_flag = request.args.get("google", "")
        return render_template("login.html", google=google_flag)

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    user = get_user_by_email(email)
    if (not user) or (not check_password_hash(user["password_hash"], password)):
        return render_template("login.html", google="")

    session["user_email"] = user["email"]
    session["user_name"] = user["full_name"]
    return redirect(url_for("traffic_page"))


@app.route("/register", methods=["POST"])
def register_user():
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not full_name or not email or not password:
        return redirect(url_for("login_page"))

    if get_user_by_email(email):
        return redirect(url_for("login_page"))

    password_hash = generate_password_hash(password)
    create_user(full_name, email, password_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    session["user_email"] = email
    session["user_name"] = full_name
    return redirect(url_for("traffic_page"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# =========================
# UI PAGES
# =========================
@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/traffic")
@login_required
def traffic_page():
    return render_template("index.html")


@app.route("/services")
@login_required
def services_page():
    return render_template("services.html")


@app.route("/inventory")
@login_required
def inventory_page():
    return render_template("inventory.html")


@app.route("/security")
@login_required
def security_page():
    return render_template("security.html")


@app.route("/quick-analysis")
@login_required
def quick_analysis_page():
    return render_template("quick_analysis.html")


# =========================
# API ROUTES
# =========================
@app.route("/api/traffic/start")
@login_required
def api_start_capture():
    command = [
        TSHARK_PATH, "-i", INTERFACE_NO, "-n",
        "-a", "duration:3",
        "-c", "20",
        "-Y", "ip",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-E", "separator=|"
    ]

    output, error = run_tshark(command)
    if output is None:
        return jsonify({"error": error}), 500

    packets = []
    for line in output.splitlines():
        parts = [p.strip() for p in line.split("|")]
        while len(parts) < 4:
            parts.append("-")
        packets.append({
            "no": parts[0],
            "src": parts[1],
            "dst": parts[2],
            "len": parts[3]
        })

    return jsonify({"count": len(packets), "packets": packets})


@app.route("/api/security/scan")
@login_required
def api_security_scan():
    payload, error = capture_security_scan()
    if payload is None:
        return jsonify({"error": error}), 500
    return jsonify(payload)


@app.route("/api/security/history")
@login_required
def api_security_history():
    try:
        days = int(request.args.get("days", 2))
        return jsonify(fetch_security_history(days))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/inventory/scan")
@login_required
def api_inventory_scan():
    payload, error = capture_inventory_devices()
    if payload is None:
        return jsonify({"error": error}), 500

    run_id, saved_at = insert_inventory_run(payload["devices"])
    payload["run_id"] = run_id
    payload["saved_at"] = saved_at
    return jsonify(payload)


@app.route("/api/inventory/history")
@login_required
def api_inventory_history():
    try:
        days = int(request.args.get("days", 2))
        return jsonify(get_history_summary(days))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
