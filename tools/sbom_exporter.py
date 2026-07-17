#!/usr/bin/env python3
"""
GMT SBOM Exporter - Phase 1: CycloneDX Basis
=============================================
Generiert ein CycloneDX 1.6 SBOM aus den container_dependencies eines GMT-Runs.

Verwendung:
    python tools/sbom_exporter.py --run-id <uuid>
    python tools/sbom_exporter.py --run-id <uuid> --output sbom.json
    python tools/sbom_exporter.py --list-runs
"""

import sys
import re
import argparse
from pathlib import Path

# GMT-Root ins sys.path damit lib-Importe funktionieren
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.db import DB  # noqa: E402  (nach sys.path.insert)

from packageurl import PackageURL
from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot6


# ---------------------------------------------------------------------------
# Mapping: GMT-Paketmanager → CycloneDX purl-type
# ---------------------------------------------------------------------------
PURL_TYPE = {
    'apk':      'apk',
    'dpkg':     'deb',
    'pip':      'pypi',
    'npm':      'npm',
    'composer': 'composer',
    'maven':    'maven',
    'pecl':     'pecl',
}


def split_version_arch(version_str: str) -> tuple[str, str | None]:
    """
    Trennt Version und Architektur aus dem kombinierten String.

    Beispiele:
        '1.0.5-r1 x86_64'              → ('1.0.5-r1', 'x86_64')
        '2.4.12 amd64'                  → ('2.4.12', 'amd64')
        '4:11.2.0-1ubuntu1 amd64'       → ('4:11.2.0-1ubuntu1', 'amd64')
        '3.0043 all'                    → ('3.0043', 'all')
        '3.11.0'                        → ('3.11.0', None)
    """
    known_archs = {'x86_64', 'amd64', 'arm64', 'armhf', 'i386', 'all', 'noarch', 'any'}
    parts = version_str.rsplit(' ', 1)
    if len(parts) == 2 and parts[1].lower() in known_archs:
        return parts[0], parts[1]
    return version_str, None


def detect_distro(os_string: str, pkg_manager: str) -> str | None:
    """
    Leitet den distro-Qualifier für den purl aus dem OS-String ab.

    'Alpine Linux v3.23' + 'apk'  → 'alpine-3.23'
    'Ubuntu 22.04.3 LTS' + 'dpkg' → 'ubuntu-22.04'
    'Debian GNU/Linux 11' + 'dpkg' → 'debian-11'
    """
    if not os_string:
        return None

    if pkg_manager == 'apk':
        m = re.search(r'Alpine[^\d]*(\d+\.\d+)', os_string, re.IGNORECASE)
        if m:
            return f'alpine-{m.group(1)}'

    elif pkg_manager == 'dpkg':
        m = re.search(r'(Ubuntu)[^\d]*(\d+\.\d+)', os_string, re.IGNORECASE)
        if m:
            return f'ubuntu-{m.group(2)}'
        m = re.search(r'(Debian)[^\d]*(\d+)', os_string, re.IGNORECASE)
        if m:
            return f'debian-{m.group(2)}'

    return None


def detect_namespace(os_string: str, pkg_manager: str) -> str | None:
    """Namespace-Teil des purl (nur für apk und dpkg relevant)."""
    if pkg_manager == 'apk':
        return 'alpine'
    if pkg_manager == 'dpkg':
        if os_string and 'ubuntu' in os_string.lower():
            return 'ubuntu'
        return 'debian'
    return None


def make_purl(
    name: str,
    version: str,
    arch: str | None,
    pkg_manager: str,
    namespace: str | None,
    distro: str | None,
) -> PackageURL | None:
    """Erzeugt einen PackageURL für ein Paket."""
    purl_type = PURL_TYPE.get(pkg_manager)
    if not purl_type:
        return None  # unbekannter Paketmanager → purl weglassen

    qualifiers: dict[str, str] = {}
    # 'all' / 'noarch' sind architekturunabhängig → kein arch-qualifier nötig
    if arch and arch not in ('all', 'noarch', 'any'):
        qualifiers['arch'] = arch
    if distro:
        qualifiers['distro'] = distro

    return PackageURL(
        type=purl_type,
        namespace=namespace,
        name=name,
        version=version,
        qualifiers=qualifiers if qualifiers else None,
    )


# ---------------------------------------------------------------------------
# Hauptlogik: container_dependencies → CycloneDX-Komponenten
# ---------------------------------------------------------------------------

def parse_container_deps(container_deps: dict) -> list[Component]:
    """
    Wandelt container_dependencies (JSONB aus GMT DB) in CycloneDX-Komponenten um.

    Struktur der Eingabe:
        {
          "<container_name>": {
            "<pkg_manager>": {
              "scope": "system",
              "dependencies": {
                "<pkg_name>": { "version": "x.y.z arch", "hash": "..." }
              }
            },
            "source": { "os": "Alpine Linux v3.23", ... }
          }
        }
    """
    components: list[Component] = []
    seen_purls: set[str] = set()  # Duplikate über Container hinweg vermeiden

    for container_name, container_data in container_deps.items():
        source = container_data.get('source', {})
        os_string = source.get('os', '')

        for pkg_manager, pkg_data in container_data.items():
            if pkg_manager == 'source':
                continue
            if not isinstance(pkg_data, dict) or 'dependencies' not in pkg_data:
                continue

            distro = detect_distro(os_string, pkg_manager)
            namespace = detect_namespace(os_string, pkg_manager)
            dependencies: dict = pkg_data['dependencies']

            for pkg_name, pkg_info in dependencies.items():
                version_raw = pkg_info.get('version', '')
                version, arch = split_version_arch(version_raw)
                pkg_hash = pkg_info.get('hash')  # SHA256, nur bei dpkg

                purl = make_purl(pkg_name, version, arch, pkg_manager, namespace, distro)
                purl_str = str(purl) if purl else f'{pkg_manager}:{pkg_name}@{version}'

                # Duplikate überspringen (gleiches Paket in mehreren Containern)
                if purl_str in seen_purls:
                    continue
                seen_purls.add(purl_str)

                component = Component(
                    type=ComponentType.LIBRARY,
                    name=pkg_name,
                    version=version,
                    purl=purl,
                )

                # Fehlenden purl explizit dokumentieren (NTIA Known Unknowns)
                if purl is None:
                    component.properties.add(Property(
                        name='green-coding:purl-missing-reason',
                        value=f'unbekannter Paketmanager: {pkg_manager}',
                    ))

                # Hash hinzufügen wenn vorhanden (dpkg liefert SHA256 des Paketfiles)
                if pkg_hash:
                    try:
                        from cyclonedx.model import HashType, HashAlgorithm
                        component.hashes.add(HashType(
                            alg=HashAlgorithm.SHA_256,
                            content=pkg_hash,
                        ))
                    except Exception:
                        pass  # Hash-API kann sich je nach cyclonedx-version unterscheiden

                components.append(component)

    return components


def enrich_metadata(bom: Bom, run: dict, container_deps: dict) -> None:
    """
    Ergänzt BOM-Metadaten für NTIA-Konformität und GMT-spezifische Daten.

    Felder:
      - authors        → NTIA: Author of SBOM Data
      - tools          → welches Tool hat das SBOM erzeugt
      - lifecycles     → NTIA-empfohlen: "operations" (runtime, nicht statisch)
      - component      → Subject des SBOMs: Container-Image mit Hash
      - properties     → GMT-spezifisch: run-id, run-name, uri (forensic SBOM)
    """

    # 1. NTIA Pflicht: Author of SBOM Data
    try:
        from cyclonedx.model.contact import OrganizationalContact
        bom.metadata.authors.add(OrganizationalContact(
            name='Green Coding Solutions GmbH',
        ))
    except Exception:
        pass

    # 2. Tool-Angabe (Best Practice / Rückverfolgbarkeit)
    try:
        from cyclonedx.model.tool import ToolsType
        tool_component = Component(
            type=ComponentType.APPLICATION,
            name='GMT SBOM Exporter',
            version='1.0.0',
        )
        bom.metadata.tools = ToolsType(components={tool_component})
    except Exception:
        try:
            from cyclonedx.model.tool import Tool
            bom.metadata.tools.tools.add(Tool(
                vendor='Green Coding Solutions GmbH',
                name='GMT SBOM Exporter',
                version='1.0.0',
            ))
        except Exception:
            pass

    # 3. Lifecycle Phase: "operations" (runtime-Erfassung, NTIA-empfohlen)
    #    Differenziert GMT von statischen Tools wie Syft (die "build" erfassen)
    #    PredefinedLifecycle ist die konkrete Unterklasse von Lifecycle (Union-Typ in v11)
    try:
        from cyclonedx.model.lifecycle import PredefinedLifecycle, LifecyclePhase
        bom.metadata.lifecycles.add(PredefinedLifecycle(phase=LifecyclePhase.OPERATIONS))
    except Exception:
        pass

    # 4. Subject des SBOMs: Container-Image mit Image-Hash
    #    Nur bei genau einem Container sinnvoll eindeutig befüllbar
    try:
        containers = {k: v for k, v in container_deps.items()}
        if len(containers) == 1:
            container_name, container_data = next(iter(containers.items()))
            source = container_data.get('source', {})
            image_name = source.get('image', container_name)
            image_hash = source.get('hash', '')  # z.B. "sha256:2307b5a0..."

            subject = Component(
                type=ComponentType.CONTAINER,
                name=image_name,
            )
            if image_hash and image_hash.startswith('sha256:'):
                from cyclonedx.model import HashType, HashAlgorithm
                subject.hashes.add(HashType(
                    alg=HashAlgorithm.SHA_256,
                    content=image_hash.removeprefix('sha256:'),
                ))
            bom.metadata.component = subject
    except Exception:
        pass

    # 5. GMT-spezifische Properties (forensic SBOM use case)
    #    Erlaubt historische Zuordnung: welcher Run hat welche Pakete verwendet
    for prop_name, prop_value in [
        ('green-coding:run-id',   str(run['id'])),
        ('green-coding:run-name', str(run.get('name') or '')),
        ('green-coding:uri',      str(run.get('uri') or '')),
    ]:
        if prop_value:
            bom.metadata.properties.add(Property(name=prop_name, value=prop_value))


# ---------------------------------------------------------------------------
# Phase 2: Energy Extension
# ---------------------------------------------------------------------------

def fetch_energy_metrics(run_id: str) -> list[dict]:
    """
    Liest alle Energie- und CO2-Metriken für einen Run aus der GMT-Datenbank.

    Erfasst dynamisch alle Provider-Kombinationen (Linux RAPL, Windows Scaphandre,
    PSU-Hardware, xgboost-Modell, GPU, macOS powermetrics, etc.) ohne Hardcoding
    spezifischer Metriken — funktioniert auf allen GMT-Plattformen.

    Filterkriterien:
      - *_energy_*        → Energieverbrauch (typisch: uJ)
      - *_carbon_*        → CO2-Emissionen (typisch: ugCO2e), OHNE carbon_intensity
      - carbon_intensity_* → Kohlenstoffintensität (typisch: gCO2e/kWh)
    """
    db = DB()
    rows = db.fetch_all(
        '''
        SELECT
            mm.metric,
            mm.detail_name,
            mm.unit,
            SUM(mv.value) AS total
        FROM measurement_values mv
        JOIN measurement_metrics mm ON mv.measurement_metric_id = mm.id
        WHERE mm.run_id = %s
          AND (
              mm.metric LIKE '%%_energy_%%'
              OR (mm.metric LIKE '%%_carbon_%%' AND mm.metric NOT LIKE 'carbon_intensity_%%')
              OR mm.metric LIKE 'carbon_intensity_%%'
          )
        GROUP BY mm.metric, mm.detail_name, mm.unit
        ORDER BY mm.metric, mm.detail_name
        ''',
        (run_id,),
        fetch_mode='dict',
    )
    return rows or []


def add_energy_to_bom(bom: Bom, energy_rows: list[dict]) -> int:
    """
    Fügt Energie- und CO2-Metriken als green-coding: Properties in die BOM-Metadaten ein.

    Property-Schema:
        green-coding:measurement:{metric}:{detail_name} = {total} {unit}

    Beispiele:
        green-coding:measurement:cpu_energy_rapl_msr_component:cpu_package = 2021536527 uJ
        green-coding:measurement:psu_carbon_ac_xgboost_machine:[MACHINE] = 387411 ugCO2e
        green-coding:measurement:carbon_intensity_static_machine:static = 342 gCO2e/kWh

    Der detail_name kommt direkt aus der GMT-DB und identifiziert den Sub-Sensor
    (z.B. CPU-Domain, Container-Name, Gerätebezeichnung).
    """
    count = 0
    for row in energy_rows:
        metric      = row['metric']
        detail_name = row['detail_name'] or ''
        unit        = row['unit'] or ''
        total       = row['total']

        # Wert als Integer wenn möglich (Energie-Werte sind immer ganzzahlig in GMT)
        try:
            value_str = str(int(total))
        except (ValueError, TypeError):
            value_str = str(round(float(total), 4))

        prop_name  = f'green-coding:measurement:{metric}:{detail_name}'
        prop_value = f'{value_str} {unit}'.strip()

        bom.metadata.properties.add(Property(name=prop_name, value=prop_value))
        count += 1

    return count


def build_bom(run_id: str) -> tuple[Bom, dict]:
    """Liest einen GMT-Run aus der DB und erzeugt ein CycloneDX BOM."""
    db = DB()

    run = db.fetch_one(
        '''
        SELECT id, name, created_at, uri, container_dependencies
        FROM runs
        WHERE id = %s
        ''',
        (run_id,),
        fetch_mode='dict',
    )

    if not run:
        print(f'Fehler: Run {run_id} nicht gefunden.', file=sys.stderr)
        sys.exit(1)

    if not run['container_dependencies']:
        print(f'Fehler: Run {run_id} hat keine container_dependencies.', file=sys.stderr)
        sys.exit(1)

    bom = Bom()
    container_deps = run['container_dependencies']
    components = parse_container_deps(container_deps)

    for c in components:
        bom.components.add(c)

    enrich_metadata(bom, run, container_deps)

    # Phase 2: Energiedaten aus GMT-DB → green-coding: Properties
    energy_rows = fetch_energy_metrics(run_id)
    energy_count = add_energy_to_bom(bom, energy_rows)

    # -----------------------------------------------------------------------
    # NTIA Known Unknowns:
    # Abhängigkeitsbeziehungen (direkt vs. transitiv) sind in Phase 1 NICHT
    # erfasst. CycloneDX compositions mit aggregate="not_complete_transitive"
    # wird in Phase 4 (Dependency Graph) ergänzt.
    # -----------------------------------------------------------------------

    meta = {
        'run_id':        str(run['id']),
        'run_name':      run.get('name', ''),
        'created_at':    str(run.get('created_at', '')),
        'uri':           run.get('uri', ''),
        'components':    len(components),
        'energy_metrics': energy_count,
    }

    return bom, meta


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def list_runs():
    """Zeigt alle Runs mit container_dependencies an."""
    db = DB()
    rows = db.fetch_all(
        '''
        SELECT id, name, created_at
        FROM runs
        WHERE container_dependencies IS NOT NULL
        ORDER BY created_at DESC
        ''',
        fetch_mode='dict',
    )
    if not rows:
        print('Keine Runs mit container_dependencies gefunden.')
        return
    print(f'{"UUID":38}  {"Name":40}  Erstellt')
    print('-' * 100)
    for r in rows:
        print(f'{str(r["id"]):38}  {str(r.get("name","") or ""):40}  {r["created_at"]}')


def main():
    parser = argparse.ArgumentParser(
        description='GMT SBOM Exporter — CycloneDX 1.6',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--run-id', help='GMT Run UUID')
    parser.add_argument('--output', '-o', help='Ausgabedatei (Standard: stdout)')
    parser.add_argument('--list-runs', action='store_true', help='Alle Runs mit Deps auflisten')
    args = parser.parse_args()

    if args.list_runs:
        list_runs()
        return

    if not args.run_id:
        parser.error('--run-id ist erforderlich (oder --list-runs)')

    bom, meta = build_bom(args.run_id)

    outputter = JsonV1Dot6(bom)
    json_str = outputter.output_as_string(indent=2)

    if args.output:
        Path(args.output).write_text(json_str, encoding='utf-8')
        print(f'SBOM geschrieben: {args.output}', file=sys.stderr)
        print(f'Komponenten:      {meta["components"]}', file=sys.stderr)
        print(f'Energiemetriken:  {meta["energy_metrics"]}', file=sys.stderr)
        print(f'Run:              {meta["run_id"]}', file=sys.stderr)
        print(f'Erstellt:         {meta["created_at"]}', file=sys.stderr)
    else:
        print(json_str)


if __name__ == '__main__':
    try:
        main()
    finally:
        DB().shutdown()
