#!/usr/bin/env python3
"""
GMT SBOM → SQLite Importer
===========================
Liest eine CycloneDX 1.6 sbom.json und importiert alle Daten in eine
lokale SQLite-Datenbank (sbom.db).

Mehrfachimport desselben Runs ist idempotent (UPSERT / IGNORE).

Verwendung:
    python tools/sbom_to_db.py sbom.json
    python tools/sbom_to_db.py sbom.json --db sbom.db
    python tools/sbom_to_db.py sbom.json --db sbom.db --verbose

Schema:
    runs            — Run-Metadaten (run_id, name, uri, container, ...)
    packages        — Komponenten (name, version, purl_type, license, purl)
    dependencies    — Kanten des Dependency Graphs (source → target)
    energy_metrics  — Energie- und CO2-Metriken pro Run
"""

import argparse
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    run_name        TEXT,
    uri             TEXT,
    container_name  TEXT,
    container_hash  TEXT,
    sbom_timestamp  TEXT,
    imported_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS packages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    bom_ref     TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT,
    purl_type   TEXT,
    purl        TEXT,
    license     TEXT,
    UNIQUE(run_id, bom_ref)
);

CREATE TABLE IF NOT EXISTS dependencies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES runs(run_id),
    source_bom_ref  TEXT NOT NULL,
    target_bom_ref  TEXT NOT NULL,
    UNIQUE(run_id, source_bom_ref, target_bom_ref)
);

CREATE TABLE IF NOT EXISTS energy_metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(run_id),
    metric      TEXT NOT NULL,
    detail_name TEXT,
    unit        TEXT,
    value       REAL,
    UNIQUE(run_id, metric, detail_name)
);

-- Indizes für schnelle Lookups
CREATE INDEX IF NOT EXISTS idx_packages_run   ON packages(run_id);
CREATE INDEX IF NOT EXISTS idx_packages_name  ON packages(name);
CREATE INDEX IF NOT EXISTS idx_packages_purl  ON packages(purl_type);
CREATE INDEX IF NOT EXISTS idx_deps_run       ON dependencies(run_id);
CREATE INDEX IF NOT EXISTS idx_deps_source    ON dependencies(source_bom_ref);
CREATE INDEX IF NOT EXISTS idx_energy_run     ON energy_metrics(run_id);
"""


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def purl_type_from_purl(purl: str) -> str | None:
    m = re.match(r'pkg:([^/]+)/', purl or '')
    return m.group(1) if m else None


def license_from_component(comp: dict) -> str | None:
    """Extrahiert den ersten Lizenz-String aus component.licenses."""
    licenses = comp.get('licenses', [])
    if not licenses:
        return None
    first = licenses[0]
    # CycloneDX 1.6: {"expression": "MIT"} oder {"license": {"name": "MIT"}}
    if 'expression' in first:
        return first['expression']
    if 'license' in first:
        lic = first['license']
        return lic.get('id') or lic.get('name')
    return None


def parse_sbom(sbom: dict) -> dict:
    """
    Extrahiert alle relevanten Felder aus dem CycloneDX 1.6 SBOM.
    Gibt ein Dict mit run, packages, dependencies, energy zurück.
    """
    # --- Run-Metadaten aus metadata ---
    meta = sbom.get('metadata', {})
    props = {p['name']: p['value'] for p in meta.get('properties', [])}

    run_id   = props.get('green-coding:run-id', '')
    run_name = props.get('green-coding:run-name', '')
    uri      = props.get('green-coding:uri', '')

    container_name = None
    container_hash = None
    meta_comp = meta.get('component')
    if meta_comp:
        container_name = meta_comp.get('name')
        hashes = meta_comp.get('hashes', [])
        if hashes:
            container_hash = hashes[0].get('content')

    sbom_timestamp = meta.get('timestamp', '')
    root_bom_ref   = meta_comp.get('bom-ref', '') if meta_comp else ''

    run = {
        'run_id':         run_id,
        'run_name':       run_name,
        'uri':            uri,
        'container_name': container_name,
        'container_hash': container_hash,
        'sbom_timestamp': sbom_timestamp,
    }

    # --- Pakete ---
    packages = []
    for comp in sbom.get('components', []):
        purl = comp.get('purl', '')
        packages.append({
            'bom_ref':   comp.get('bom-ref', ''),
            'name':      comp.get('name', ''),
            'version':   comp.get('version', ''),
            'purl_type': purl_type_from_purl(purl),
            'purl':      purl,
            'license':   license_from_component(comp),
        })

    # --- Dependency-Edges (Root-Edges ausschließen) ---
    dependencies = []
    for dep_entry in sbom.get('dependencies', []):
        source = dep_entry.get('ref', '')
        if source == root_bom_ref:
            continue  # Root→Alle überspringen (zu generisch)
        for target in dep_entry.get('dependsOn', []):
            dependencies.append({
                'source_bom_ref': source,
                'target_bom_ref': target,
            })

    # --- Energiemetriken aus Properties ---
    # Format: green-coding:measurement:{metric}:{detail_name} = {value} {unit}
    energy = []
    prefix = 'green-coding:measurement:'
    for key, val in props.items():
        if not key.startswith(prefix):
            continue
        rest = key[len(prefix):]
        # Letzten Doppelpunkt-Teil als detail_name, Rest als metric
        parts = rest.rsplit(':', 1)
        if len(parts) == 2:
            metric, detail_name = parts
        else:
            metric, detail_name = rest, ''

        # Wert und Einheit trennen: "12345 uJ" → 12345.0, "uJ"
        val_parts = val.strip().split(' ', 1)
        try:
            value = float(val_parts[0])
        except ValueError:
            value = None
        unit = val_parts[1] if len(val_parts) > 1 else ''

        energy.append({
            'metric':      metric,
            'detail_name': detail_name,
            'unit':        unit,
            'value':       value,
        })

    return {
        'run':          run,
        'packages':     packages,
        'dependencies': dependencies,
        'energy':       energy,
        'root_bom_ref': root_bom_ref,
    }


# ---------------------------------------------------------------------------
# Datenbank-Import
# ---------------------------------------------------------------------------

def import_to_db(data: dict, db_path: Path, verbose: bool = False) -> dict:
    """
    Importiert die geparsten SBOM-Daten in die SQLite-Datenbank.
    Gibt Statistiken zurück.
    """
    con = sqlite3.connect(db_path)
    con.execute('PRAGMA foreign_keys = ON')
    con.executescript(SCHEMA)

    run      = data['run']
    run_id   = run['run_id']
    now      = datetime.now(timezone.utc).isoformat()

    # Run UPSERT
    con.execute("""
        INSERT INTO runs (run_id, run_name, uri, container_name, container_hash,
                          sbom_timestamp, imported_at)
        VALUES (:run_id, :run_name, :uri, :container_name, :container_hash,
                :sbom_timestamp, :imported_at)
        ON CONFLICT(run_id) DO UPDATE SET
            run_name       = excluded.run_name,
            uri            = excluded.uri,
            container_name = excluded.container_name,
            container_hash = excluded.container_hash,
            sbom_timestamp = excluded.sbom_timestamp,
            imported_at    = excluded.imported_at
    """, {**run, 'imported_at': now})

    # Pakete UPSERT
    pkg_count = 0
    for pkg in data['packages']:
        con.execute("""
            INSERT INTO packages (run_id, bom_ref, name, version, purl_type, purl, license)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, bom_ref) DO UPDATE SET
                name      = excluded.name,
                version   = excluded.version,
                purl_type = excluded.purl_type,
                purl      = excluded.purl,
                license   = excluded.license
        """, (run_id, pkg['bom_ref'], pkg['name'], pkg['version'],
              pkg['purl_type'], pkg['purl'], pkg['license']))
        pkg_count += 1

    # Dependencies IGNORE (Duplikate sind ok)
    dep_count = 0
    for dep in data['dependencies']:
        con.execute("""
            INSERT OR IGNORE INTO dependencies (run_id, source_bom_ref, target_bom_ref)
            VALUES (?, ?, ?)
        """, (run_id, dep['source_bom_ref'], dep['target_bom_ref']))
        dep_count += 1

    # Energiemetriken UPSERT
    energy_count = 0
    for e in data['energy']:
        con.execute("""
            INSERT INTO energy_metrics (run_id, metric, detail_name, unit, value)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(run_id, metric, detail_name) DO UPDATE SET
                unit  = excluded.unit,
                value = excluded.value
        """, (run_id, e['metric'], e['detail_name'], e['unit'], e['value']))
        energy_count += 1

    con.commit()
    con.close()

    stats = {
        'run_id':    run_id,
        'packages':  pkg_count,
        'deps':      dep_count,
        'energy':    energy_count,
    }

    if verbose:
        print(f'Run:             {run_id}')
        print(f'Container:       {run["container_name"]}')
        print(f'Pakete:          {pkg_count}')
        print(f'Dep-Edges:       {dep_count}')
        print(f'Energiemetriken: {energy_count}')

    return stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='GMT SBOM → SQLite Importer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('sbom', help='Pfad zur sbom.json')
    parser.add_argument('--db', default='sbom.db', help='SQLite-Datei (Standard: sbom.db)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Detaillierte Ausgabe')
    args = parser.parse_args()

    sbom_path = Path(args.sbom)
    if not sbom_path.exists():
        print(f'Fehler: {sbom_path} nicht gefunden.')
        raise SystemExit(1)

    sbom = json.loads(sbom_path.read_text(encoding='utf-8'))
    data = parse_sbom(sbom)

    if not data['run']['run_id']:
        print('Warnung: run_id nicht gefunden — SBOM enthält keine green-coding:run-id Property.')

    db_path = Path(args.db)
    stats = import_to_db(data, db_path, verbose=args.verbose)

    print(f'Importiert: {stats["packages"]} Pakete, {stats["deps"]} Deps, '
          f'{stats["energy"]} Metriken → {db_path}')


if __name__ == '__main__':
    main()
