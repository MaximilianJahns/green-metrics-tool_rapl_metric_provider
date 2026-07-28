#!/usr/bin/env python3
"""
GMT SBOM Datenbank — Query-Demo
================================
Zeigt nützliche Abfragen auf der sbom.db SQLite-Datenbank.
Verwendbar als Vorlage für ML-Vorbereitung mit pandas.

Verwendung:
    python tools/sbom_query.py
    python tools/sbom_query.py --db sbom.db
"""

import argparse
import sqlite3
from pathlib import Path

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


def connect(db_path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    return con


def section(title: str):
    print(f'\n{"─" * 60}')
    print(f'  {title}')
    print('─' * 60)


# ---------------------------------------------------------------------------
# Query 1: Übersicht aller Runs
# ---------------------------------------------------------------------------
def q_runs(con):
    section('Alle Runs in der Datenbank')
    rows = con.execute("""
        SELECT
            r.run_id,
            r.run_name,
            r.container_name,
            COUNT(DISTINCT p.id)  AS pakete,
            COUNT(DISTINCT d.id)  AS dep_edges,
            COUNT(DISTINCT e.id)  AS metriken
        FROM runs r
        LEFT JOIN packages     p ON p.run_id = r.run_id
        LEFT JOIN dependencies d ON d.run_id = r.run_id
        LEFT JOIN energy_metrics e ON e.run_id = r.run_id
        GROUP BY r.run_id
        ORDER BY r.sbom_timestamp DESC
    """).fetchall()

    print(f'{"Run-Name":<40}  {"Container":<25}  Pkgs  Deps  Metr.')
    print('-' * 100)
    for r in rows:
        print(f'{(r["run_name"] or ""):<40}  {(r["container_name"] or ""):<25}  '
              f'{r["pakete"]:>4}  {r["dep_edges"]:>4}  {r["metriken"]:>5}')


# ---------------------------------------------------------------------------
# Query 2: Welche Runs enthalten ein bestimmtes Paket?
# ---------------------------------------------------------------------------
def q_find_package(con, package_name: str = 'flask'):
    section(f'Runs die Paket "{package_name}" enthalten')
    rows = con.execute("""
        SELECT r.run_name, p.version, p.purl_type, p.license
        FROM packages p
        JOIN runs r ON r.run_id = p.run_id
        WHERE LOWER(p.name) = LOWER(?)
        ORDER BY r.sbom_timestamp DESC
    """, (package_name,)).fetchall()

    if not rows:
        print(f'  Kein Run enthält "{package_name}".')
        return
    for r in rows:
        print(f'  Run: {r["run_name"]}  |  Version: {r["version"]}  '
              f'|  Typ: {r["purl_type"]}  |  Lizenz: {r["license"]}')


# ---------------------------------------------------------------------------
# Query 3: Paket-Typen-Verteilung pro Run
# ---------------------------------------------------------------------------
def q_purl_distribution(con):
    section('Pakettyp-Verteilung pro Run')
    rows = con.execute("""
        SELECT
            r.run_name,
            p.purl_type,
            COUNT(*) AS anzahl
        FROM packages p
        JOIN runs r ON r.run_id = p.run_id
        GROUP BY r.run_id, p.purl_type
        ORDER BY r.run_name, anzahl DESC
    """).fetchall()

    current_run = None
    for r in rows:
        if r['run_name'] != current_run:
            current_run = r['run_name']
            print(f'\n  {current_run}')
        ptype = r['purl_type'] or 'unbekannt'
        print(f'    {ptype:<15} {r["anzahl"]:>3} Pakete')


# ---------------------------------------------------------------------------
# Query 4: Direktabhängigkeiten eines Pakets (über bom_ref aufgelöst)
# ---------------------------------------------------------------------------
def q_deps_of(con, run_id: str, package_name: str = 'flask'):
    section(f'Abhängigkeiten von "{package_name}"')

    # bom_ref des Pakets ermitteln
    pkg = con.execute("""
        SELECT bom_ref FROM packages
        WHERE run_id = ? AND LOWER(name) = LOWER(?)
        LIMIT 1
    """, (run_id, package_name)).fetchone()

    if not pkg:
        print(f'  "{package_name}" nicht in Run {run_id[:8]}... gefunden.')
        return

    deps = con.execute("""
        SELECT p.name, p.version, p.purl_type
        FROM dependencies d
        JOIN packages p ON p.bom_ref = d.target_bom_ref AND p.run_id = d.run_id
        WHERE d.run_id = ? AND d.source_bom_ref = ?
        ORDER BY p.name
    """, (run_id, pkg['bom_ref'])).fetchall()

    if not deps:
        print(f'  Keine Abhängigkeiten gefunden.')
        return
    for d in deps:
        print(f'  → {d["name"]}=={d["version"]}  ({d["purl_type"]})')


# ---------------------------------------------------------------------------
# Query 5: Energie-Vergleich über Runs (CPU-Package)
# ---------------------------------------------------------------------------
def q_energy_comparison(con):
    section('CPU-Energie-Vergleich (cpu_energy_rapl_msr_component:cpu_package)')
    rows = con.execute("""
        SELECT r.run_name, e.value, e.unit
        FROM energy_metrics e
        JOIN runs r ON r.run_id = e.run_id
        WHERE e.metric = 'cpu_energy_rapl_msr_component'
          AND e.detail_name = 'cpu_package'
        ORDER BY e.value DESC
    """).fetchall()

    if not rows:
        print('  Keine RAPL-CPU-Energiemessungen gefunden.')
        return
    for r in rows:
        val_mj = (r['value'] or 0) / 1_000_000
        print(f'  {(r["run_name"] or ""):<45}  {val_mj:>10.2f} J')


# ---------------------------------------------------------------------------
# Query 6: ML Feature-Matrix (pandas)
# ---------------------------------------------------------------------------
def q_ml_features(con):
    section('ML Feature-Matrix (pandas DataFrame)')
    if not HAS_PANDAS:
        print('  pandas nicht installiert. Bitte: pip install pandas')
        return

    # Eine Zeile pro (run, paket) mit Energie-Features
    df_pkgs = pd.read_sql_query("""
        SELECT
            p.run_id,
            r.run_name,
            r.container_name,
            p.name        AS pkg_name,
            p.version,
            p.purl_type,
            p.license
        FROM packages p
        JOIN runs r ON r.run_id = p.run_id
    """, con)

    df_energy = pd.read_sql_query("""
        SELECT
            run_id,
            metric || ':' || COALESCE(detail_name, '') AS feature,
            value
        FROM energy_metrics
    """, con)

    # Energie-Features als Pivot breit machen
    if not df_energy.empty:
        df_pivot = df_energy.pivot_table(
            index='run_id', columns='feature', values='value', aggfunc='first'
        ).reset_index()
        df = df_pkgs.merge(df_pivot, on='run_id', how='left')
    else:
        df = df_pkgs

    print(f'  Shape: {df.shape[0]} Zeilen × {df.shape[1]} Spalten')
    print(f'  Spalten: {list(df.columns[:8])} ...')
    print(f'\n  Erste 3 Zeilen:')
    print(df[['run_name', 'pkg_name', 'version', 'purl_type']].head(3).to_string(index=False))

    # CSV-Export
    out = Path('sbom_features.csv')
    df.to_csv(out, index=False)
    print(f'\n  → Feature-Matrix gespeichert: {out}')
    return df


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='GMT SBOM Datenbank Query-Demo')
    parser.add_argument('--db', default='sbom.db', help='SQLite-Datei (Standard: sbom.db)')
    parser.add_argument('--package', default='flask', help='Paketname für Dep-Lookup (Standard: flask)')
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f'Fehler: {db_path} nicht gefunden. Zuerst sbom_to_db.py ausführen.')
        raise SystemExit(1)

    con = connect(db_path)

    q_runs(con)
    q_find_package(con, args.package)
    q_purl_distribution(con)
    q_energy_comparison(con)

    # Dep-Lookup: ersten Run nehmen der das gesuchte Paket enthält
    pkg_run = con.execute("""
        SELECT run_id FROM packages
        WHERE LOWER(name) = LOWER(?)
        LIMIT 1
    """, (args.package,)).fetchone()
    if pkg_run:
        q_deps_of(con, pkg_run['run_id'], args.package)

    q_ml_features(con)

    con.close()
    print()


if __name__ == '__main__':
    main()
