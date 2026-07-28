#!/usr/bin/env python3
"""
GMT SBOM Exporter - Phase 1-3: CycloneDX Basis + Energy + Lizenzen
====================================================================
Generiert ein CycloneDX 1.6 SBOM aus den container_dependencies eines GMT-Runs.

Verwendung:
    python tools/sbom_exporter.py --run-id <uuid>
    python tools/sbom_exporter.py --run-id <uuid> --output sbom.json
    python tools/sbom_exporter.py --run-id <uuid> --no-licenses
    python tools/sbom_exporter.py --list-runs
"""

import sys
import re
import argparse
import io
import tarfile
import threading
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import json as json_mod
from concurrent.futures import ThreadPoolExecutor, as_completed
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
# Phase 3: Lizenz-Lookup via externe Paketregistry-APIs
# ---------------------------------------------------------------------------

_LICENSE_CACHE: dict[str, str | None] = {}  # "type:name@version" → SPDX-String oder None
_RESPONSE_CACHE: dict[str, bytes | None] = {}  # URL → rohe HTTP-Response (geteilt für License + Deps)

_HTTP_TIMEOUT = 4  # Sekunden pro Request


def _http_get(url: str) -> bytes | None:
    """HTTP-GET mit URL-Cache und Timeout. Gibt None bei Fehler zurück.

    Der Response-Cache stellt sicher, dass Lizenz- und Dependency-Lookup
    dieselbe API-Antwort teilen ohne Doppel-Requests.
    """
    if url in _RESPONSE_CACHE:
        return _RESPONSE_CACHE[url]
    try:
        with urllib.request.urlopen(url, timeout=_HTTP_TIMEOUT) as r:
            result: bytes | None = r.read()
    except Exception:
        result = None
    _RESPONSE_CACHE[url] = result
    return result


def _fetch_pypi(name: str, version: str) -> str | None:
    """PyPI JSON API → info.license, Fallback: License-Classifiers"""
    data = _http_get(f'https://pypi.org/pypi/{name}/{version}/json')
    if not data:
        return None
    try:
        info = json_mod.loads(data).get('info', {})
        # 1. Direktes Lizenzfeld (z.B. "MIT", "Apache-2.0")
        lic = (info.get('license') or '').strip()
        if lic:
            return lic
        # 2. Fallback: PyPI-Classifiers
        #    "License :: OSI Approved :: MIT License" → "MIT License"
        #    "License :: OSI Approved :: Apache Software License" → "Apache Software License"
        for classifier in info.get('classifiers', []):
            if classifier.startswith('License :: OSI Approved :: '):
                return classifier.split(' :: ')[-1]
        return None
    except Exception:
        return None


def _fetch_npm(name: str, version: str) -> str | None:
    """npm Registry API → license"""
    data = _http_get(f'https://registry.npmjs.org/{name}/{version}')
    if not data:
        return None
    try:
        lic = json_mod.loads(data).get('license')
        if isinstance(lic, dict):
            return lic.get('type')
        return lic or None
    except Exception:
        return None


def _fetch_composer(name: str, version: str) -> str | None:
    """Packagist API → license[]"""
    # composer name ist vendor/package
    data = _http_get(f'https://packagist.org/packages/{name}.json')
    if not data:
        return None
    try:
        pkgs = json_mod.loads(data).get('package', {}).get('versions', {})
        # Version mit oder ohne 'v'-Prefix suchen
        for key in (version, f'v{version}'):
            entry = pkgs.get(key, {})
            if entry:
                licenses = entry.get('license', [])
                return ' AND '.join(licenses) if licenses else None
        return None
    except Exception:
        return None


def _fetch_maven(name: str, version: str) -> str | None:
    """Maven Central POM XML → <licenses><license><name>"""
    # name ist typisch "group:artifact" oder nur "artifact"
    parts = name.split(':')
    if len(parts) == 2:
        group, artifact = parts
    else:
        return None
    group_path = group.replace('.', '/')
    url = f'https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}.pom'
    data = _http_get(url)
    if not data:
        return None
    try:
        root = ET.fromstring(data)
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        names = [e.text for e in root.findall('.//m:license/m:name', ns) if e.text]
        if not names:
            # ohne Namespace versuchen
            names = [e.text for e in root.findall('.//license/name') if e.text]
        return ' AND '.join(names) if names else None
    except Exception:
        return None


def _fetch_pecl(name: str, _version: str) -> str | None:
    """PECL REST API → license"""
    data = _http_get(f'https://pecl.php.net/rest/p/{name}/info.xml')
    if not data:
        return None
    try:
        root = ET.fromstring(data)
        # Namespace ignorieren
        for child in root.iter():
            if child.tag.endswith('license') and child.text:
                return child.text.strip()
        return None
    except Exception:
        return None


def _fetch_alpine(name: str, version: str, distro: str = 'edge') -> str | None:
    """Alpine Linux packages HTML → license (kein JSON-API verfügbar)"""
    # distro ist z.B. "alpine-3.23" → branch "v3.23"
    # version ist Paket-Version "1.2.3-r0", enthält keine Distro-Info
    m = re.match(r'alpine-(\d+)\.(\d+)', distro)
    branch = f'v{m.group(1)}.{m.group(2)}' if m else 'edge'
    data = _http_get(f'https://pkgs.alpinelinux.org/packages?name={name}&branch={branch}')
    if not data:
        return None
    try:
        html = data.decode('utf-8', errors='replace')
        # HTML: <td class="license"><span class="hint--right" aria-label="MIT">MIT</span></td>
        m2 = re.search(r'<td class="license">\s*<span[^>]*>\s*([^<]+?)\s*</span>', html)
        return m2.group(1).strip() if m2 else None
    except Exception:
        return None


def _fetch_debian(name: str, _version: str) -> str | None:
    """Debian/Ubuntu: kein zuverlässiges REST-API → Known Unknown"""
    return None


# Erweiterbare Map: purl-type → Fetch-Funktion
# Neue Paketmanager hier eintragen (cargo, gem, golang, nuget, ...)
LICENSE_FETCHERS: dict[str, callable] = {
    'pypi':     _fetch_pypi,
    'npm':      _fetch_npm,
    'composer': _fetch_composer,
    'maven':    _fetch_maven,
    'pecl':     _fetch_pecl,
    'apk':      _fetch_alpine,
    'deb':      _fetch_debian,
    # Zukünftig:
    # 'cargo':   _fetch_crates_io,
    # 'gem':     _fetch_rubygems,
    # 'golang':  _fetch_pkg_go_dev,
    # 'nuget':   _fetch_nuget,
}


# ---------------------------------------------------------------------------
# Phase 4: Dependency Graph
# ---------------------------------------------------------------------------

def _normalize_pkg_name(name: str, purl_type: str) -> str:
    """Normalisiert Paketnamen für Registry-übergreifenden Vergleich."""
    n = name.lower()
    if purl_type == 'pypi':
        # PEP 503: Hyphens, underscores und Punkte sind äquivalent
        return re.sub(r'[-_\.]+', '_', n)
    return n


def _deps_pypi(name: str, version: str) -> list[str]:
    """PyPI requires_dist → Liste direkter Abhängigkeitsnamen."""
    data = _http_get(f'https://pypi.org/pypi/{name}/{version}/json')
    if not data:
        return []
    try:
        requires = json_mod.loads(data).get('info', {}).get('requires_dist') or []
        deps = []
        for req in requires:
            # Optionale Abhängigkeiten (extras) überspringen
            if ';' in req and 'extra ==' in req.split(';')[1]:
                continue
            # Nur Paketnamen extrahieren (vor Versionsoperatoren)
            pkg_name = re.split(r'[>=<!;\s\[\(]', req)[0].strip()
            if pkg_name:
                deps.append(_normalize_pkg_name(pkg_name, 'pypi'))
        return deps
    except Exception:
        return []


def _deps_npm(name: str, version: str) -> list[str]:
    """npm registry dependencies dict → Liste direkter Abhängigkeitsnamen."""
    data = _http_get(f'https://registry.npmjs.org/{name}/{version}')
    if not data:
        return []
    try:
        return list(json_mod.loads(data).get('dependencies', {}).keys())
    except Exception:
        return []


def _deps_composer(name: str, version: str) -> list[str]:
    """Packagist require dict → Liste direkter Abhängigkeitsnamen."""
    data = _http_get(f'https://packagist.org/packages/{name}.json')
    if not data:
        return []
    try:
        pkgs = json_mod.loads(data).get('package', {}).get('versions', {})
        for key in (version, f'v{version}'):
            entry = pkgs.get(key, {})
            if entry:
                require = entry.get('require', {})
                # php, ext-* und lib-* sind keine echten Pakete
                return [
                    k for k in require.keys()
                    if not re.match(r'^(php|ext-|lib-)', k)
                ]
        return []
    except Exception:
        return []


def _deps_maven(name: str, version: str) -> list[str]:
    """Maven POM <dependencies> → Liste 'groupId:artifactId'."""
    parts = name.split(':')
    if len(parts) != 2:
        return []
    group, artifact = parts
    group_path = group.replace('.', '/')
    url = f'https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}.pom'
    data = _http_get(url)
    if not data:
        return []
    try:
        root = ET.fromstring(data)
        ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
        deps = []
        for dep in root.findall('.//m:dependency', ns) or root.findall('.//dependency'):
            scope_el = dep.find('m:scope', ns) or dep.find('scope')
            if scope_el is not None and scope_el.text in ('test', 'provided', 'system'):
                continue
            g_el = dep.find('m:groupId', ns) or dep.find('groupId')
            a_el = dep.find('m:artifactId', ns) or dep.find('artifactId')
            if g_el is not None and a_el is not None and g_el.text and a_el.text:
                deps.append(f'{g_el.text}:{a_el.text}')
        return deps
    except Exception:
        return []


def _deps_pecl(name: str, _version: str) -> list[str]:
    """PECL info.xml <deps> → minimale Abhängigkeitsliste."""
    data = _http_get(f'https://pecl.php.net/rest/p/{name}/info.xml')
    if not data:
        return []
    try:
        root = ET.fromstring(data)
        deps = []
        for child in root.iter():
            if child.tag.endswith('}name') or child.tag == 'name':
                parent_tag = child.tag.replace('{http://pear.php.net/dtd/rest.packageinfo}', '')
                if parent_tag == 'name':
                    continue  # das ist der Paketname selbst
            # PECL deps sind oft in <d:dep><d:name>...</d:name></d:dep> Strukturen
            # Zu komplex für einfaches Parsen — minimal halten
        return deps
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Alpine APKINDEX-Cache (pro Branch einmalig geladen)
# ---------------------------------------------------------------------------
_APKINDEX_CACHE: dict[str, dict[str, list[str]]] = {}  # branch → {pkg → [deps]}
_APKINDEX_LOCK = threading.Lock()


def _load_apkindex(branch: str, arch: str = 'x86_64') -> dict[str, list[str]]:
    """
    Lädt Alpine APKINDEX.tar.gz für main + community und gibt
    {pkg_name → [dep_pkg_names]} zurück.

    APKINDEX-Format (Textdatei, Blöcke durch Leerzeilen getrennt):
        P:apk-tools
        V:3.0.6-r0
        D:libapk=3.0.6-r0 so:libc.musl-x86_64.so.1 musl>=1.0

    D:-Feld enthält:
        - echte Paketnamen (evt. mit Versionsoperator: pkg>=1.0, pkg=1.0)
        - so:libXYZ.so.1       → shared-library Referenz (kein Paketname)
        - cmd:...              → Kommando-Referenz (kein Paketname)
        - pc:...               → pkg-config Referenz (kein Paketname)
    """
    deps_map: dict[str, list[str]] = {}

    for repo in ('main', 'community'):
        url = (
            f'https://dl-cdn.alpinelinux.org/alpine/{branch}'
            f'/{repo}/{arch}/APKINDEX.tar.gz'
        )
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                raw = r.read()
        except Exception:
            continue

        try:
            with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
                member = tf.extractfile('APKINDEX')
                if not member:
                    continue
                text = member.read().decode('utf-8', errors='replace')
        except Exception:
            continue

        for block in text.split('\n\n'):
            pkg_name = None
            pkg_deps: list[str] = []
            for line in block.splitlines():
                if line.startswith('P:'):
                    pkg_name = line[2:].strip()
                elif line.startswith('D:'):
                    for token in line[2:].split():
                        # Versionsoperator entfernen: libapk=3.0.6-r0 → libapk
                        dep_name = re.split(r'[>=<!]', token)[0]
                        # so:, cmd:, pc: etc. sind keine Paketnamen
                        if ':' not in dep_name and dep_name:
                            pkg_deps.append(dep_name)
            if pkg_name:
                deps_map[pkg_name] = pkg_deps

    return deps_map


def _deps_apk(name: str, _version: str, distro: str = 'edge') -> list[str]:
    """
    Alpine Paket-Abhängigkeiten via APKINDEX.tar.gz (einmalig pro Branch geladen).

    Viel effizienter als HTML-Scraping: ein einziger HTTP-Request pro Branch
    deckt alle Pakete in main + community ab.
    """
    m = re.match(r'alpine-(\d+)\.(\d+)', distro)
    branch = f'v{m.group(1)}.{m.group(2)}' if m else 'edge'

    if branch not in _APKINDEX_CACHE:
        with _APKINDEX_LOCK:
            if branch not in _APKINDEX_CACHE:   # Double-Check nach Lock-Erwerb
                print(f'  APKINDEX laden: {branch} ...', file=sys.stderr)
                _APKINDEX_CACHE[branch] = _load_apkindex(branch)

    return _APKINDEX_CACHE[branch].get(name, [])


# Erweiterbare Map: purl-type → Dependency-Fetcher
# Neue Paketmanager hier eintragen (cargo, gem, golang, nuget, ...)
DEP_FETCHERS: dict[str, callable] = {
    'pypi':     _deps_pypi,
    'npm':      _deps_npm,
    'composer': _deps_composer,
    'maven':    _deps_maven,
    'apk':      _deps_apk,
    # pecl: zu komplex für zuverlässiges Parsen
    # deb: kein zuverlässiges REST-API für Dependency-Graph
    # Zukünftig:
    # 'cargo':  _deps_crates_io,
    # 'gem':    _deps_rubygems,
    # 'golang': _deps_pkg_go_dev,
    # 'nuget':  _deps_nuget,
}


def build_dependency_graph(
    bom,
    components: list[Component],
    purls: list[PackageURL | None],
    fetch_deps: bool = True,
) -> int:
    """
    Erstellt den CycloneDX Dependency Graph (bom.dependencies).

    Für jeden Paketmanager mit API-Unterstützung werden direkte Abhängigkeiten
    abgefragt und als Dependency-Edges eingetragen. Unbekannte Abhängigkeiten
    (apk, deb) werden mit leerer Dependency-Liste registriert (Known Unknown).

    Das Root-Component (Container-Image in metadata.component) wird als
    abhängig von allen installierten Paketen eingetragen.

    Gibt Anzahl der hinzugefügten Dependency-Edges zurück.
    """
    from cyclonedx.model.dependency import Dependency as CdxDependency

    # Lookup-Tabelle: normalisierter Name → Component (für Dep-Name-Matching)
    name_to_comp: dict[str, Component] = {}
    for comp, purl in zip(components, purls):
        if purl:
            key = _normalize_pkg_name(purl.name, purl.type)
            name_to_comp[key] = comp

    total_edges = 0

    if fetch_deps:
        print(f'  Abhängigkeiten abrufen: {len(components)} Pakete ...', file=sys.stderr)

        def _dep_kwargs(purl) -> dict:
            """Extrahiert purl-Qualifier als kwargs für den Dep-Fetcher (z.B. distro für apk)."""
            if purl.type == 'apk' and purl.qualifiers:
                q = purl.qualifiers if isinstance(purl.qualifiers, dict) else {}
                if 'distro' in q:
                    return {'distro': q['distro']}
            return {}

        # Nur Pakete mit bekanntem Dep-Fetcher abfragen
        fetchable = [
            (purl.type, purl.name, comp.version, i, _dep_kwargs(purl))
            for i, (comp, purl) in enumerate(zip(components, purls))
            if purl and comp.version and purl.type in DEP_FETCHERS
        ]

        dep_map: dict[int, list[str]] = {}

        def _fetch_dep_one(args):
            purl_type, name, version, idx, kwargs = args
            try:
                return idx, DEP_FETCHERS[purl_type](name, version, **kwargs)
            except TypeError:
                return idx, DEP_FETCHERS[purl_type](name, version)

        with ThreadPoolExecutor(max_workers=10) as ex:
            for idx, deps in ex.map(_fetch_dep_one, fetchable):
                dep_map[idx] = deps

        # Dependency-Edges in BOM eintragen
        for i, (comp, purl) in enumerate(zip(components, purls)):
            if not purl:
                bom.register_dependency(comp)
                continue

            dep_names = dep_map.get(i, [])
            dep_comps: list[Component] = []

            for dep_name in dep_names:
                key = _normalize_pkg_name(dep_name, purl.type)
                dep_comp = name_to_comp.get(key)
                if dep_comp and dep_comp is not comp:
                    dep_comps.append(dep_comp)

            if dep_comps:
                bom.register_dependency(comp, dep_comps)
                total_edges += len(dep_comps)
            else:
                bom.register_dependency(comp)  # Known Unknown: Deps nicht ermittelbar

    else:
        # Alle Komponenten ohne Deps registrieren (fixiert die CycloneDX-Warning)
        for comp in components:
            bom.register_dependency(comp)

    # Root-Component (Container-Image) hängt von allen installierten Paketen ab
    if bom.metadata.component and components:
        bom.register_dependency(bom.metadata.component, components)
        total_edges += len(components)

    return total_edges


# ---------------------------------------------------------------------------
# Hilfs-Cache-Key (geteilt zwischen Phase 3 + 4)
# ---------------------------------------------------------------------------

def _cache_key(purl_type: str, name: str, version: str) -> str:
    return f'{purl_type}:{name}@{version}'


def fetch_license(purl_type: str, name: str, version: str, **kwargs) -> str | None:
    """
    Fragt die Lizenz eines Pakets via externe Registry-API ab.
    Ergebnis wird in-memory gecacht (pro Exporter-Aufruf).

    kwargs werden an den Fetcher weitergegeben (z.B. distro='alpine-3.23' für apk).
    """
    key = _cache_key(purl_type, name, version)
    if key in _LICENSE_CACHE:
        return _LICENSE_CACHE[key]

    fetcher = LICENSE_FETCHERS.get(purl_type)
    if fetcher is None:
        result = None
    else:
        try:
            result = fetcher(name, version, **kwargs)
        except TypeError:
            result = fetcher(name, version)  # Fetcher unterstützt kwargs nicht

    _LICENSE_CACHE[key] = result
    return result


def fetch_licenses_parallel(
    packages: list[tuple],  # [(purl_type, name, version, **kwargs), ...]
    max_workers: int = 10,
) -> dict[str, str | None]:
    """
    Fragt Lizenzen für mehrere Pakete parallel ab.
    Jeder Eintrag ist (purl_type, name, version) oder (purl_type, name, version, extra_kwargs).
    Gibt Dict {cache_key → license_string} zurück.
    """
    results: dict[str, str | None] = {}
    todo = []
    for item in packages:
        purl_type, name, version = item[0], item[1], item[2]
        extra = item[3] if len(item) > 3 else {}
        key = _cache_key(purl_type, name, version)
        if key in _LICENSE_CACHE:
            results[key] = _LICENSE_CACHE[key]
        else:
            todo.append((purl_type, name, version, extra, key))

    if not todo:
        return results

    def _fetch_one(args):
        purl_type, name, version, extra, key = args
        return key, fetch_license(purl_type, name, version, **extra)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for key, lic in ex.map(_fetch_one, todo):
            results[key] = lic

    return results


def apply_licenses_to_components(
    components: list[Component],
    purls: list[PackageURL | None],
    fetch_licenses: bool = True,
) -> int:
    """
    Fragt Lizenzen für alle Komponenten ab und fügt sie als component.licenses ein.
    Gibt Anzahl erfolgreich aufgelöster Lizenzen zurück.

    Für apk-Pakete wird der distro-Qualifier aus dem PURL extrahiert und
    an den Alpine-Fetcher weitergegeben (Branch-Auflösung).
    """
    if not fetch_licenses:
        return 0

    # Pakete für Parallel-Lookup sammeln
    # Eintrag: (purl_type, name, version, extra_kwargs, idx)
    lookup: list[tuple] = []
    for idx, (comp, purl) in enumerate(zip(components, purls)):
        if purl and comp.version:
            extra: dict = {}
            if purl.type == 'apk' and purl.qualifiers:
                # qualifiers ist dict oder str; PackageURL parst zu dict
                q = purl.qualifiers if isinstance(purl.qualifiers, dict) else {}
                if 'distro' in q:
                    extra['distro'] = q['distro']
            lookup.append((purl.type, purl.name, comp.version, extra, idx))

    if not lookup:
        return 0

    print(f'  Lizenzen abrufen: {len(lookup)} Pakete ...', file=sys.stderr)
    pkg_items = [(t, n, v, e) for t, n, v, e, _ in lookup]
    license_map = fetch_licenses_parallel(pkg_items)

    resolved = 0
    for purl_type, name, version, extra, idx in lookup:
        key = _cache_key(purl_type, name, version)
        lic_str = license_map.get(key)

        comp = components[idx]
        if lic_str:
            try:
                # In cyclonedx-python-lib v11:
                #   LicenseExpression(value=...)   → SPDX-Ausdruck (z.B. "MIT", "Apache-2.0")
                #   DisjunctiveLicense(name=...)   → Freitext-Lizenzname (nicht-SPDX)
                # LicenseRepository (SortedSet) nimmt beide via .add()
                from cyclonedx.model.license import LicenseExpression, DisjunctiveLicense
                try:
                    comp.licenses.add(LicenseExpression(value=lic_str))
                except Exception:
                    comp.licenses.add(DisjunctiveLicense(name=lic_str))
                resolved += 1
            except Exception:
                pass
        else:
            # Known Unknown: keine Lizenz via API ermittelbar
            comp.properties.add(Property(
                name='green-coding:license-missing-reason',
                value=f'kein API-Zugriff für purl-type: {purl_type}',
            ))

    return resolved


# ---------------------------------------------------------------------------
# Hauptlogik: container_dependencies → CycloneDX-Komponenten
# ---------------------------------------------------------------------------

def parse_container_deps(
    container_deps: dict,
) -> tuple[list[Component], list[PackageURL | None]]:
    """
    Wandelt container_dependencies (JSONB aus GMT DB) in CycloneDX-Komponenten um.

    Gibt (components, purls) zurück — beide Listen haben gleiche Länge und gleiche
    Reihenfolge, damit apply_licenses_to_components purl-Typ + Name zuordnen kann.

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
    purls: list[PackageURL | None] = []
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
                purls.append(purl)

    return components, purls


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


def build_bom(run_id: str, fetch_licenses: bool = True, fetch_deps: bool = True) -> tuple[Bom, dict]:
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
    components, purls = parse_container_deps(container_deps)

    for c in components:
        bom.components.add(c)

    enrich_metadata(bom, run, container_deps)

    # Phase 2: Energiedaten aus GMT-DB → green-coding: Properties
    energy_rows = fetch_energy_metrics(run_id)
    energy_count = add_energy_to_bom(bom, energy_rows)

    # Phase 3: Lizenzen via externe Paketregistry-APIs
    license_count = apply_licenses_to_components(components, purls, fetch_licenses)

    # Phase 4: Dependency Graph
    dep_edges = build_dependency_graph(bom, components, purls, fetch_deps)

    meta = {
        'run_id':         str(run['id']),
        'run_name':       run.get('name', ''),
        'created_at':     str(run.get('created_at', '')),
        'uri':            run.get('uri', ''),
        'components':     len(components),
        'energy_metrics': energy_count,
        'licenses':       license_count,
        'dep_edges':      dep_edges,
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
    parser.add_argument(
        '--no-licenses', action='store_true',
        help='Lizenz-Lookup via externe APIs überspringen (schneller, offline-fähig)',
    )
    parser.add_argument(
        '--no-deps', action='store_true',
        help='Dependency-Graph-Lookup via externe APIs überspringen',
    )
    args = parser.parse_args()

    if args.list_runs:
        list_runs()
        return

    if not args.run_id:
        parser.error('--run-id ist erforderlich (oder --list-runs)')

    bom, meta = build_bom(
        args.run_id,
        fetch_licenses=not args.no_licenses,
        fetch_deps=not args.no_deps,
    )

    outputter = JsonV1Dot6(bom)
    json_str = outputter.output_as_string(indent=2)

    if args.output:
        Path(args.output).write_text(json_str, encoding='utf-8')
        print(f'SBOM geschrieben: {args.output}', file=sys.stderr)
        print(f'Komponenten:      {meta["components"]}', file=sys.stderr)
        print(f'Energiemetriken:  {meta["energy_metrics"]}', file=sys.stderr)
        print(f'Lizenzen:         {meta["licenses"]}', file=sys.stderr)
        print(f'Dep-Edges:        {meta["dep_edges"]}', file=sys.stderr)
        print(f'Run:              {meta["run_id"]}', file=sys.stderr)
        print(f'Erstellt:         {meta["created_at"]}', file=sys.stderr)
    else:
        print(json_str)


if __name__ == '__main__':
    try:
        main()
    finally:
        DB().shutdown()
