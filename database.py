# database.py
import sqlite3
from datetime import datetime

DB_PATH = 'events.db'


def inicializar_banco():
    """Creates tables if they don't exist yet."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            src_ip          TEXT    NOT NULL,
            dst_ip          TEXT    NOT NULL,
            protocol        TEXT,
            dst_port        INTEGER,
            bytes           INTEGER,
            abuse_score     INTEGER DEFAULT 0,
            total_reports   INTEGER DEFAULT 0,
            status          TEXT    DEFAULT 'CLEAN',
            action          TEXT    DEFAULT 'MONITOR',
            country_code    TEXT    DEFAULT 'XX',
            isp             TEXT    DEFAULT 'unknown',
            otx_pulses      INTEGER DEFAULT 0
        )
    ''')

    # Safe migration: add new columns if the DB already existed
    for col, definition in [
        ("country_code", "TEXT DEFAULT 'XX'"),
        ("isp",          "TEXT DEFAULT 'unknown'"),
        ("otx_pulses",   "INTEGER DEFAULT 0"),
    ]:
        try:
            cursor.execute(f"ALTER TABLE events ADD COLUMN {col} {definition}")
        except sqlite3.OperationalError:
            pass  # column already exists, all good

    conn.commit()
    conn.close()
    print("[DB] Database initialized: events.db")


def salvar_evento(dados: dict):
    """Persists a processed event. Grafana reads from here."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO events
        (timestamp, src_ip, dst_ip, protocol, dst_port,
         bytes, abuse_score, total_reports, status, action,
         country_code, isp, otx_pulses)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        dados["srcip"],
        dados["dstip"],
        dados.get("proto",         "tcp"),
        dados.get("dstport",        0),
        dados.get("bytes",          0),
        dados.get("abuse_score",    0),
        dados.get("total_reports",  0),
        dados.get("classificacao",  "CLEAN"),
        dados.get("acao",           "MONITOR"),
        dados.get("country_code",   "XX"),
        dados.get("isp",            "unknown"),
        dados.get("otx_pulses",     0),
    ))
    conn.commit()
    conn.close()