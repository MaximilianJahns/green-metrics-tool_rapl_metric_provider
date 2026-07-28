#!/usr/bin/env python3
"""
GMT Overnight Runner
====================
Startet GMT-Runs wiederholt über Nacht, erfasst vor jedem Run den
Systemzustand und verknüpft ihn mit der GMT-run_id in der SQLite-DB.

Verwendung:
    python tools/sbom/overnight_runner.py --config overnight_config.json
    python tools/sbom/overnight_runner.py --runs 50 --wait 30 --db sbom.db

Schema (neu in sbom.db):
    system_snapshots — Systemzustand vor jedem Run, verknüpft mit run_id

Voraussetzung:
    pip install psutil psycopg
"""

import argparse
import json
import platform
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
import psycopg

# ---------------------------------------------------------------------------
# GMT-Verbindung
# ---------------------------------------------------------------------------
GMT_DSN = dict(host='localhost', port=9573, dbname='green-coding',
               user='postgres', password='test1234')

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SNAPSHOT_SCHEMA = """
CREATE TABLE IF NOT EXISTS system_snapshots (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT,                      -- GMT run_id (nach dem Run befüllt)
    snapshot_at         TEXT NOT NULL,             -- Zeitstempel vor dem Run (UTC ISO)
    cpu_percent         REAL,                      -- CPU-Auslastung % (1s Messung)
    cpu_freq_mhz        REAL,                      -- aktuelle CPU-Frequenz
    cpu_cores_logical   INTEGER,                   -- logische Kerne
    ram_total_mb        REAL,
    ram_available_mb    REAL,
    ram_percent         REAL,
    process_count       INTEGER,                   -- Anzahl laufender Prozesse
    power_plan          TEXT,                      -- Windows Power Plan (wenn verfügbar)
    net_bytes_sent_mb   REAL,                      -- Netzwerk seit Boot
    net_bytes_recv_mb   REAL,
    disk_read_mb        REAL,                      -- Disk I/O seit Boot
    disk_write_mb       REAL,
    os_name             TEXT,
    os_version          TEXT,
    hostname            TEXT,
    notes               TEXT                       -- freier Kommentar (z.B. "Nacht-Lauf #3")
);

CREATE INDEX IF NOT EXISTS idx_snap_run_id ON system_snapshots(run_id);
CREATE INDEX IF NOT EXISTS idx_snap_at    ON system_snapshots(snapshot_at);
"""


# ---------------------------------------------------------------------------
# Systemzustand erfassen
# ---------------------------------------------------------------------------

def get_power_plan() -> str:
    """Windows Power Plan via powercfg auslesen."""
    try:
        result = subprocess.run(
            ['powercfg', '/getactivescheme'],
            capture_output=True, text=True, timeout=5
        )
        # Ausgabe: "Power Scheme GUID: ... (High performance)"
        line = result.stdout.strip()
        if '(' in line and ')' in line:
            return line[line.index('(') + 1:line.rindex(')')]
        return line[:80]
    except Exception:
        return 'unbekannt'


def capture_system_state(notes: str = '') -> dict:
    """Erfasst aktuellen Systemzustand. Gibt Dict zurück."""
    cpu_pct = psutil.cpu_percent(interval=1)
    freq    = psutil.cpu_freq()
    ram     = psutil.virtual_memory()
    net     = psutil.net_io_counters()
    disk    = psutil.disk_io_counters()

    return {
        'snapshot_at':       datetime.now(timezone.utc).isoformat(),
        'cpu_percent':       cpu_pct,
        'cpu_freq_mhz':      freq.current if freq else None,
        'cpu_cores_logical': psutil.cpu_count(logical=True),
        'ram_total_mb':      ram.total / 1024 / 1024,
        'ram_available_mb':  ram.available / 1024 / 1024,
        'ram_percent':       ram.percent,
        'process_count':     len(psutil.pids()),
        'power_plan':        get_power_plan() if platform.system() == 'Windows' else 'N/A',
        'net_bytes_sent_mb': net.bytes_sent / 1024 / 1024,
        'net_bytes_recv_mb': net.bytes_recv / 1024 / 1024,
        'disk_read_mb':      disk.read_bytes / 1024 / 1024 if disk else None,
        'disk_write_mb':     disk.write_bytes / 1024 / 1024 if disk else None,
        'os_name':           platform.system(),
        'os_version':        platform.version()[:100],
        'hostname':          platform.node(),
        'notes':             notes,
    }


def save_snapshot(con: sqlite3.Connection, snap: dict) -> int:
    """Speichert Snapshot in SQLite, gibt rowid zurück."""
    cur = con.execute("""
        INSERT INTO system_snapshots
            (run_id, snapshot_at, cpu_percent, cpu_freq_mhz, cpu_cores_logical,
             ram_total_mb, ram_available_mb, ram_percent, process_count,
             power_plan, net_bytes_sent_mb, net_bytes_recv_mb,
             disk_read_mb, disk_write_mb, os_name, os_version, hostname, notes)
        VALUES
            (:run_id, :snapshot_at, :cpu_percent, :cpu_freq_mhz, :cpu_cores_logical,
             :ram_total_mb, :ram_available_mb, :ram_percent, :process_count,
             :power_plan, :net_bytes_sent_mb, :net_bytes_recv_mb,
             :disk_read_mb, :disk_write_mb, :os_name, :os_version, :hostname, :notes)
    """, {**snap, 'run_id': None})
    con.commit()
    return cur.lastrowid


def link_run_id(con: sqlite3.Connection, snapshot_id: int, run_id: str):
    """Verknüpft Snapshot nachträglich mit GMT run_id."""
    con.execute("UPDATE system_snapshots SET run_id = ? WHERE id = ?",
                (run_id, snapshot_id))
    con.commit()


# ---------------------------------------------------------------------------
# GMT-Run starten und run_id ermitteln
# ---------------------------------------------------------------------------

def get_latest_run_id_after(gmt_conn, after_ts: datetime) -> str | None:
    """Findet den neuesten GMT-Run der nach after_ts erstellt wurde."""
    cur = gmt_conn.cursor()
    cur.execute("""
        SELECT id::text FROM runs
        WHERE created_at > %s
        ORDER BY created_at DESC
        LIMIT 1
    """, (after_ts,))
    row = cur.fetchone()
    return row[0] if row else None


def run_gmt(gmt_cmd: list[str], timeout: int = 3600) -> tuple[bool, str]:
    """
    Startet einen GMT-Run als Subprocess.
    Gibt (success, stderr) zurück.
    """
    try:
        result = subprocess.run(
            gmt_cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, f'Timeout nach {timeout}s'
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Hauptschleife
# ---------------------------------------------------------------------------

def run_overnight(args):
    db_path = Path(args.db)
    gmt_cmd = args.cmd

    # SQLite vorbereiten
    con = sqlite3.connect(db_path)
    con.execute('PRAGMA journal_mode=WAL')
    con.executescript(SNAPSHOT_SCHEMA)

    # GMT-Verbindung
    gmt_conn = psycopg.connect(**GMT_DSN)

    total    = args.runs
    wait_sec = args.wait
    success  = 0
    failed   = 0

    print(f'GMT Overnight Runner gestartet')
    print(f'Runs geplant : {total}')
    print(f'Pause        : {wait_sec}s zwischen Runs')
    print(f'GMT-Befehl   : {" ".join(gmt_cmd)}')
    print(f'SQLite-DB    : {db_path}')
    print('─' * 60)

    for i in range(1, total + 1):
        label = f'[{i:>3}/{total}]'
        notes = f'Nacht-Lauf #{i} von {total}'

        # 1. Systemzustand erfassen
        print(f'{label} Systemcheck...', end=' ', flush=True)
        snap      = capture_system_state(notes=notes)
        snap_id   = save_snapshot(con, snap)
        ts_before = datetime.now(timezone.utc)

        print(f'CPU {snap["cpu_percent"]:.1f}%  '
              f'RAM {snap["ram_percent"]:.1f}%  '
              f'Proz. {snap["process_count"]}  '
              f'Plan: {snap["power_plan"]}')

        # Warnung bei hoher Grundlast
        if snap['cpu_percent'] > 20:
            print(f'  ⚠ CPU-Last > 20% — Messung könnte ungenau sein')

        # 2. GMT-Run starten
        print(f'{label} GMT läuft...', end=' ', flush=True)
        t0 = time.time()
        ok, stderr = run_gmt(gmt_cmd, timeout=args.timeout)
        elapsed = time.time() - t0

        if not ok:
            failed += 1
            print(f'FEHLER nach {elapsed:.0f}s')
            print(f'  {stderr[:200]}')
            # Snapshot bleibt ohne run_id (run_id = NULL)
        else:
            success += 1
            print(f'OK ({elapsed:.0f}s)', end=' ', flush=True)

            # 3. run_id aus GMT-DB ermitteln
            time.sleep(2)  # kurz warten bis DB geschrieben
            run_id = get_latest_run_id_after(gmt_conn, ts_before)
            if run_id:
                link_run_id(con, snap_id, run_id)
                print(f'→ {run_id[:8]}...')
            else:
                print(f'→ run_id nicht gefunden')

        # 4. SBOM exportieren (optional)
        if ok and run_id and not args.no_sbom:
            sbom_file = f'sbom_tmp_{run_id[:8]}.json'
            r = subprocess.run(
                [sys.executable,
                 str(Path(args.tools_dir) / 'sbom_exporter.py'),
                 '--run-id', run_id,
                 '--output', sbom_file]
                + (['--no-licenses', '--no-deps'] if args.fast_sbom else []),
                capture_output=True, text=True
            )
            if r.returncode == 0:
                subprocess.run(
                    [sys.executable,
                     str(Path(args.tools_dir) / 'sbom_to_db.py'),
                     sbom_file, '--db', str(db_path)],
                    capture_output=True
                )
                Path(sbom_file).unlink(missing_ok=True)
                print(f'  SBOM importiert')
            else:
                print(f'  SBOM-Export übersprungen: {r.stderr.strip()[:80]}')

        # 5. Pause (außer nach letztem Run)
        if i < total:
            print(f'{label} Pause {wait_sec}s...')
            time.sleep(wait_sec)

    gmt_conn.close()
    con.close()

    print('─' * 60)
    print(f'Fertig: {success} OK  {failed} Fehler  →  {db_path}')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='GMT Overnight Runner mit Systemzustand-Erfassung',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  # 50 Runs über Nacht, 60s Pause, SBOM direkt importieren
  python tools/sbom/overnight_runner.py --runs 50 --wait 60 --cmd python runner.py --uri ../example-applications/compression/ --name "compression-test"

  # Schnell testen (3 Runs, kein SBOM)
  python tools/sbom/overnight_runner.py --runs 3 --wait 10 --no-sbom --cmd python runner.py --uri ../example-applications/stress-ng/ --name "test"

Hinweis:
  Alles nach --cmd wird als GMT-Startbefehl interpretiert.
  Der Rechner sollte während der Nacht nicht für anderes genutzt werden.
        """
    )
    parser.add_argument('--db',         default='sbom.db')
    parser.add_argument('--runs',       default=10,   type=int,  help='Anzahl Runs (Standard: 10)')
    parser.add_argument('--wait',       default=30,   type=int,  help='Pause zwischen Runs in Sekunden (Standard: 30)')
    parser.add_argument('--timeout',    default=3600, type=int,  help='Max. Laufzeit pro Run in Sekunden (Standard: 3600)')
    parser.add_argument('--tools-dir',  default='tools/sbom',    help='Pfad zu sbom_exporter.py etc.')
    parser.add_argument('--no-sbom',    action='store_true',     help='SBOM-Export nach jedem Run überspringen')
    parser.add_argument('--fast-sbom',  action='store_true',     help='SBOM ohne Lizenz- und Dep-Lookup (schneller)')
    parser.add_argument('--cmd',        nargs=argparse.REMAINDER, required=True,
                        help='GMT-Startbefehl (alles nach --cmd)')
    args = parser.parse_args()

    if not args.cmd:
        parser.error('--cmd ist erforderlich')

    run_overnight(args)


if __name__ == '__main__':
    main()
