import os
import sqlite3

# DB file stays inside project folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "netmon.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    #  Important: enable foreign key constraints (for ON DELETE CASCADE)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
    except Exception:
        pass

    return conn


def init_db():
    """Create required tables if they do not exist."""
    conn = get_conn()
    cur = conn.cursor()

    # One row per scan run
    cur.execute("""
        CREATE TABLE IF NOT EXISTS inventory_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)

    # Devices found per run (linked to inventory_runs)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS inventory_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            type TEXT NOT NULL,
            packets INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            FOREIGN KEY (run_id) REFERENCES inventory_runs(id) ON DELETE CASCADE
        )
    """)

    # Helpful indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_runs_time ON inventory_runs(scanned_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_run ON inventory_devices(run_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON inventory_devices(ip)")

    conn.commit()
    conn.close()


def insert_inventory_run(devices):
    """
    Save one scan run + its devices.
    Returns: (run_id, saved_at)
    """
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("INSERT INTO inventory_runs DEFAULT VALUES")
    run_id = cur.lastrowid

    for d in (devices or []):
        ip = str(d.get("ip", "")).strip()
        if not ip:
            continue

        dtype = str(d.get("type", "Unknown")).strip()

        try:
            packets = int(d.get("packets", 0) or 0)
        except Exception:
            packets = 0

        first_seen = d.get("first_seen")
        last_seen = d.get("last_seen")

        cur.execute("""
            INSERT INTO inventory_devices (run_id, ip, type, packets, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (run_id, ip, dtype, packets, first_seen, last_seen))

    # fetch saved time
    cur.execute("SELECT scanned_at FROM inventory_runs WHERE id = ?", (run_id,))
    row = cur.fetchone()
    saved_at = row["scanned_at"] if row else None

    conn.commit()
    conn.close()
    return run_id, saved_at


def get_history_summary(days=2):
    """
    Aggregated device history for last N days:
    - group by ip+type
    - sum packets
    - min first_seen
    - max last_seen
    """
    try:
        days = int(days)
    except Exception:
        days = 2

    days = max(1, min(days, 30))

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            d.ip AS ip,
            d.type AS type,
            SUM(COALESCE(d.packets, 0)) AS total_packets,
            MIN(d.first_seen) AS first_seen,
            MAX(d.last_seen) AS last_seen
        FROM inventory_devices d
        JOIN inventory_runs r ON r.id = d.run_id
        WHERE datetime(r.scanned_at) >= datetime('now','localtime', ?)
        GROUP BY d.ip, d.type
        ORDER BY total_packets DESC, datetime(last_seen) DESC
    """, (f"-{days} days",))

    devices = [dict(row) for row in cur.fetchall()]
    conn.close()

    internal = sum(1 for d in devices if d.get("type") == "Internal")
    external = sum(1 for d in devices if d.get("type") == "External")

    return {
        "days": days,
        "from": f"last {days} day(s)",
        "total": len(devices),
        "internal": internal,
        "external": external,
        "devices": devices
    }


def delete_old_runs(keep_days=7):
    """
    Delete inventory_runs older than keep_days.
    ON DELETE CASCADE removes inventory_devices automatically.
    """
    try:
        keep_days = int(keep_days)
    except Exception:
        keep_days = 7

    keep_days = max(1, keep_days)

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM inventory_runs
        WHERE datetime(scanned_at) < datetime('now','localtime', ?)
    """, (f"-{keep_days} days",))

    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted
