#!/usr/bin/env python3
"""
GMT → SQLite Exporter
======================
Zieht alle relevanten Daten aus der GMT-PostgreSQL-Datenbank und speichert
sie in dieselbe SQLite-Datei wie sbom_to_db.py (Standard: sbom.db).

Neue Tabellen (werden automatisch angelegt):
    gmt_phase_stats         — aggregierte Energie-/CPU-Werte pro Run & Phase
    gmt_measurement_metrics — Metrik-Definitionen pro Run
    gmt_measurement_values  — Rohe Zeitreihenwerte

Die bestehende `runs`-Tabelle wird mit GMT-Metadaten angereichert
(run_name, container_name, created_at), falls der Run bereits per
sbom_to_db.py importiert wurde. Neue Runs werden direkt eingefügt.

Verwendung:
    python tools/gmt_to_db.py
    python tools/gmt_to_db.py --db sbom.db --verbose
    python tools/gmt_to_db.py --run-id 5823fea0-... --db sbom.db

Voraussetzung:
    pip install psycopg
"""

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

try:
    import psycopg
except ImportError:
    raise SystemExit('psycopg nicht installiert. Bitte: pip install psycopg')


# ---------------------------------------------------------------------------
# Verbindungsdefaults (können per ENV oder CLI überschrieben werden)
# ---------------------------------------------------------------------------
GMT_DEFAULT = dict(
    host='localhost',
    port=9573,
    dbname='green-coding',
    user='postgres',
    password='test1234',
)


# ---------------------------------------------------------------------------
# Schema-Erweiterungen
# ---------------------------------------------------------------------------
SCHEMA_EXTENSION = """
-- GMT-Erweiterung der runs-Tabelle: created_at Spalte hinzufügen falls fehlt
-- (SQLite unterstützt kein ALTER TABLE ADD COLUMN IF NOT EXISTS direkt)

CREATE TABLE IF NOT EXISTS gmt_phase_stats (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              TEXT    NOT NULL,
    phase               TEXT    NOT NULL,
    metric              TEXT    NOT NULL,
    detail_name         TEXT,
    value               INTEGER,
    max_value           INTEGER,
    min_value           INTEGER,
    unit                TEXT,
    type                TEXT,
    hidden              INTEGER NOT NULL DEFAULT 0,
    sampling_rate_avg   INTEGER,
    sampling_rate_max   INTEGER,
    sampling_rate_95p   INTEGER,
    UNIQUE(run_id, phase, metric, detail_name)
);

CREATE TABLE IF NOT EXISTS gmt_measurement_metrics (
    id      INTEGER PRIMARY KEY,   -- Original-ID aus GMT
    run_id  TEXT    NOT NULL,
    metric  TEXT    NOT NULL,
    detail_name TEXT,
    unit    TEXT,
    UNIQUE(run_id, metric, detail_name)
);

CREATE TABLE IF NOT EXISTS gmt_measurement_values (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    measurement_metric_id   INTEGER NOT NULL
                            REFERENCES gmt_measurement_metrics(id),
    time                    INTEGER NOT NULL,   -- Mikrosekunden-Epoch
    value                   INTEGER NOT NULL,
    UNIQUE(measurement_metric_id, time)
);

CREATE INDEX IF NOT EXISTS idx_gmt_phase_run    ON gmt_phase_stats(run_id);
CREATE INDEX IF NOT EXISTS idx_gmt_phase_metric ON gmt_phase_stats(metric);
CREATE INDEX IF NOT EXISTS idx_gmt_mm_run       ON gmt_measurement_metrics(run_id);
CREATE INDEX IF NOT EXISTS idx_gmt_mv_metric    ON gmt_measurement_values(measurement_metric_id);
CREATE INDEX IF NOT EXISTS idx_gmt_mv_time      ON gmt_measurement_values(time);
"""


# ---------------------------------------------------------------------------
# Verbindungen
# ---------------------------------------------------------------------------

def gmt_connect(dsn: dict) -> psycopg.Connection:
    return psycopg.connect(**dsn)


def sqlite_connect(db_path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA foreign_keys=ON')
    return con


def ensure_schema(con: sqlite3.Connection):
    """Legt fehlende Tabellen und Indizes an."""
    con.executescript(SCHEMA_EXTENSION)
    # created_at Spalte in runs ergänzen falls noch nicht vorhanden
    cols = {row[1] for row in con.execute("PRAGMA table_info(runs)")}
    if 'created_at' not in cols:
        con.execute("ALTER TABLE runs ADD COLUMN created_at TEXT")
    if 'gmt_name' not in cols:
        con.execute("ALTER TABLE runs ADD COLUMN gmt_name TEXT")
    con.commit()


# ---------------------------------------------------------------------------
# Runs importieren / anreichern
# ---------------------------------------------------------------------------

def import_runs(gmt_cur, sqlite_con: sqlite3.Connection,
                run_id_filter: str | None, verbose: bool) -> list[str]:
    """
    Holt alle Runs (oder einen bestimmten) aus GMT und upserted sie in SQLite.
    Gibt die Liste der importierten run_ids zurück.
    """
    if run_id_filter:
        gmt_cur.execute("""
            SELECT id::text, name, created_at
            FROM runs WHERE id = %s
        """, (run_id_filter,))
    else:
        gmt_cur.execute("""
            SELECT id::text, name, created_at
            FROM runs ORDER BY created_at DESC
        """)

    rows = gmt_cur.fetchall()
    now = datetime.now(timezone.utc).isoformat()
    run_ids = []

    for run_id, name, created_at in rows:
        ts = created_at.isoformat() if created_at else None
        sqlite_con.execute("""
            INSERT INTO runs (run_id, run_name, gmt_name, created_at, imported_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                gmt_name   = excluded.gmt_name,
                created_at = excluded.created_at,
                imported_at = excluded.imported_at
        """, (run_id, name, name, ts, now))
        run_ids.append(run_id)
        if verbose:
            print(f'  Run: {name}  ({run_id[:8]}...)')

    sqlite_con.commit()
    if verbose:
        print(f'→ {len(run_ids)} Runs importiert/aktualisiert')
    return run_ids


# ---------------------------------------------------------------------------
# Phase Stats
# ---------------------------------------------------------------------------

def import_phase_stats(gmt_cur, sqlite_con: sqlite3.Connection,
                       run_ids: list[str], verbose: bool) -> int:
    gmt_cur.execute("""
        SELECT
            run_id::text, phase, metric, detail_name,
            value, max_value, min_value, unit, type, hidden,
            sampling_rate_avg, sampling_rate_max, sampling_rate_95p
        FROM phase_stats
        WHERE run_id = ANY(%s)
        ORDER BY run_id, phase, metric
    """, (run_ids,))

    rows = gmt_cur.fetchall()
    count = 0
    for row in rows:
        sqlite_con.execute("""
            INSERT INTO gmt_phase_stats
                (run_id, phase, metric, detail_name,
                 value, max_value, min_value, unit, type, hidden,
                 sampling_rate_avg, sampling_rate_max, sampling_rate_95p)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(run_id, phase, metric, detail_name) DO UPDATE SET
                value             = excluded.value,
                max_value         = excluded.max_value,
                min_value         = excluded.min_value,
                unit              = excluded.unit,
                type              = excluded.type,
                hidden            = excluded.hidden,
                sampling_rate_avg = excluded.sampling_rate_avg,
                sampling_rate_max = excluded.sampling_rate_max,
                sampling_rate_95p = excluded.sampling_rate_95p
        """, (
            row[0], row[1], row[2], row[3],
            row[4], row[5], row[6], row[7], row[8], int(row[9]),
            row[10], row[11], row[12],
        ))
        count += 1

    sqlite_con.commit()
    if verbose:
        print(f'→ {count} Phase-Stats importiert')
    return count


# ---------------------------------------------------------------------------
# Measurement Metrics + Values
# ---------------------------------------------------------------------------

def import_measurements(gmt_cur, sqlite_con: sqlite3.Connection,
                        run_ids: list[str], verbose: bool) -> tuple[int, int]:
    # Metriken
    gmt_cur.execute("""
        SELECT id, run_id::text, metric, detail_name, unit
        FROM measurement_metrics
        WHERE run_id = ANY(%s)
        ORDER BY run_id, metric
    """, (run_ids,))

    metrics = gmt_cur.fetchall()
    metric_count = 0
    for gmt_id, run_id, metric, detail_name, unit in metrics:
        sqlite_con.execute("""
            INSERT OR REPLACE INTO gmt_measurement_metrics
                (id, run_id, metric, detail_name, unit)
            VALUES (?, ?, ?, ?, ?)
        """, (gmt_id, run_id, metric, detail_name, unit))
        metric_count += 1

    sqlite_con.commit()

    # Zeitreihenwerte (können sehr groß sein → batchweise)
    if not metrics:
        if verbose:
            print('→ Keine Metriken gefunden')
        return 0, 0

    metric_ids = [m[0] for m in metrics]
    BATCH = 500

    gmt_cur.execute("""
        SELECT measurement_metric_id, time, value
        FROM measurement_values
        WHERE measurement_metric_id = ANY(%s)
        ORDER BY measurement_metric_id, time
    """, (metric_ids,))

    value_count = 0
    batch = []
    for row in gmt_cur:
        batch.append(row)
        if len(batch) >= BATCH:
            sqlite_con.executemany("""
                INSERT OR IGNORE INTO gmt_measurement_values
                    (measurement_metric_id, time, value)
                VALUES (?, ?, ?)
            """, batch)
            value_count += len(batch)
            batch = []

    if batch:
        sqlite_con.executemany("""
            INSERT OR IGNORE INTO gmt_measurement_values
                (measurement_metric_id, time, value)
            VALUES (?, ?, ?)
        """, batch)
        value_count += len(batch)

    sqlite_con.commit()

    if verbose:
        print(f'→ {metric_count} Metriken, {value_count} Zeitreihenwerte importiert')
    return metric_count, value_count


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='GMT PostgreSQL → SQLite Exporter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  python tools/gmt_to_db.py
  python tools/gmt_to_db.py --db sbom.db --verbose
  python tools/gmt_to_db.py --run-id 5823fea0-0f8b-4cc4-98f6-7616daf719fd
  python tools/gmt_to_db.py --host localhost --port 9573 --no-timeseries
        """
    )
    parser.add_argument('--db',           default='sbom.db',    help='SQLite-Datei (Standard: sbom.db)')
    parser.add_argument('--host',         default=GMT_DEFAULT['host'])
    parser.add_argument('--port',         default=GMT_DEFAULT['port'],     type=int)
    parser.add_argument('--dbname',       default=GMT_DEFAULT['dbname'])
    parser.add_argument('--user',         default=GMT_DEFAULT['user'])
    parser.add_argument('--password',     default=GMT_DEFAULT['password'])
    parser.add_argument('--run-id',       default=None,   help='Nur diesen Run importieren (UUID)')
    parser.add_argument('--no-timeseries', action='store_true',
                        help='measurement_values überspringen (schneller, weniger Speicher)')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    dsn = dict(host=args.host, port=args.port, dbname=args.dbname,
               user=args.user, password=args.password)

    db_path = Path(args.db)

    print(f'GMT  → {args.host}:{args.port}/{args.dbname}')
    print(f'SQLite → {db_path}')

    # Verbindungen aufbauen
    gmt = gmt_connect(dsn)
    sqlite_con = sqlite_connect(db_path)
    ensure_schema(sqlite_con)

    gmt_cur = gmt.cursor()

    # Import
    run_ids = import_runs(gmt_cur, sqlite_con, args.run_id, args.verbose)
    ps_count = import_phase_stats(gmt_cur, sqlite_con, run_ids, args.verbose)

    if args.no_timeseries:
        mm_count = mv_count = 0
        if args.verbose:
            print('→ Zeitreihen übersprungen (--no-timeseries)')
    else:
        mm_count, mv_count = import_measurements(gmt_cur, sqlite_con, run_ids, args.verbose)

    gmt.close()
    sqlite_con.close()

    print(f'\nFertig: {len(run_ids)} Runs | {ps_count} Phase-Stats | '
          f'{mm_count} Metriken | {mv_count} Zeitreihenwerte → {db_path}')


if __name__ == '__main__':
    main()
