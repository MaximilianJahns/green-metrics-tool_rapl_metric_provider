#!/usr/bin/env python3
"""
GMT SBOM Dependency Graph Visualizer
=====================================
Liest eine CycloneDX 1.6 sbom.json und erzeugt eine interaktive
HTML-Visualisierung des Dependency Graphs (D3.js force-directed).

Verwendung:
    python tools/sbom_graph.py sbom.json
    python tools/sbom_graph.py sbom.json --output graph.html
    python tools/sbom_graph.py sbom.json --no-open   # nicht automatisch öffnen
"""

import argparse
import json
import re
import webbrowser
from pathlib import Path

# ---------------------------------------------------------------------------
# purl-Typ → Farbe (für Knoten-Einfärbung)
# ---------------------------------------------------------------------------
PURL_COLORS = {
    'apk':      '#4CAF50',   # grün  (Alpine)
    'deb':      '#8BC34A',   # hellgrün (Debian)
    'pypi':     '#3B82F6',   # blau  (Python)
    'npm':      '#F59E0B',   # orange (Node)
    'composer': '#8B5CF6',   # lila  (PHP)
    'maven':    '#EF4444',   # rot   (Java)
    'pecl':     '#EC4899',   # pink  (PHP-Ext)
    'root':     '#1F2937',   # dunkelgrau (Container)
}
DEFAULT_COLOR = '#9CA3AF'  # grau (unbekannt)


def purl_type_from_purl(purl: str) -> str:
    """Extrahiert den purl-Typ aus 'pkg:pypi/...' → 'pypi'."""
    m = re.match(r'pkg:([^/]+)/', purl or '')
    return m.group(1) if m else 'unknown'


def build_graph(sbom: dict) -> tuple[list, list]:
    """Extrahiert Nodes und Edges aus dem CycloneDX SBOM."""
    # bom-ref → {name, version, purl_type}
    ref_map: dict[str, dict] = {}

    # Root-Component (Container-Image aus metadata)
    root_ref = None
    meta_comp = sbom.get('metadata', {}).get('component')
    if meta_comp:
        root_ref = meta_comp.get('bom-ref', '')
        ref_map[root_ref] = {
            'name':      meta_comp.get('name', 'Container'),
            'version':   meta_comp.get('version', ''),
            'purl_type': 'root',
        }

    # Alle Komponenten
    for comp in sbom.get('components', []):
        ref = comp.get('bom-ref', '')
        purl = comp.get('purl', '')
        ref_map[ref] = {
            'name':      comp.get('name', ref),
            'version':   comp.get('version', ''),
            'purl_type': purl_type_from_purl(purl),
        }

    # Nodes
    nodes = [
        {
            'id':       ref,
            'label':    f'{info["name"]}\n{info["version"]}',
            'name':     info['name'],
            'version':  info['version'],
            'type':     info['purl_type'],
            'color':    PURL_COLORS.get(info['purl_type'], DEFAULT_COLOR),
            'is_root':  ref == root_ref,
        }
        for ref, info in ref_map.items()
    ]

    # Edges (aus bom.dependencies)
    edges = []
    for dep_entry in sbom.get('dependencies', []):
        source = dep_entry.get('ref', '')
        for target in dep_entry.get('dependsOn', []):
            if source in ref_map and target in ref_map:
                edges.append({
                    'source': source,
                    'target': target,
                    'is_root_edge': source == root_ref,
                })

    return nodes, edges


def generate_html(nodes: list, edges: list, title: str) -> str:
    nodes_json = json.dumps(nodes, ensure_ascii=False)
    edges_json = json.dumps(edges, ensure_ascii=False)

    legend_entries = [
        ('Alpine (apk)',    PURL_COLORS['apk'],      'apk'),
        ('Python (pip)',    PURL_COLORS['pypi'],     'pypi'),
        ('Node (npm)',      PURL_COLORS['npm'],      'npm'),
        ('PHP (composer)',  PURL_COLORS['composer'], 'composer'),
        ('Java (maven)',    PURL_COLORS['maven'],    'maven'),
        ('Unbekannt',       DEFAULT_COLOR,           'unknown'),
        ('Container',       PURL_COLORS['root'],     'root'),
    ]
    legend_items = ''.join(
        f'<div class="legend-item active" data-type="{ptype}" onclick="toggleType(this)" '
        f'style="cursor:pointer" title="Klicken zum Aus-/Einblenden">'
        f'<span class="dot" style="background:{color}"></span>{label}</div>'
        for label, color, ptype in legend_entries
    )

    return f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }}
  #header {{ padding: 16px 24px; background: #1e293b; border-bottom: 1px solid #334155;
             display: flex; align-items: center; gap: 16px; }}
  #header h1 {{ font-size: 1.1rem; font-weight: 600; color: #f8fafc; }}
  #header .stats {{ font-size: 0.8rem; color: #94a3b8; margin-left: auto; }}
  #controls {{ padding: 8px 24px; background: #1e293b; border-bottom: 1px solid #334155;
               display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
  input[type=text] {{ background: #0f172a; border: 1px solid #475569; border-radius: 6px;
                      color: #e2e8f0; padding: 4px 10px; font-size: 0.85rem; width: 200px; }}
  input[type=text]::placeholder {{ color: #64748b; }}
  label {{ font-size: 0.8rem; color: #94a3b8; cursor: pointer; display: flex; gap: 4px; align-items: center; }}
  #legend {{ display: flex; gap: 12px; flex-wrap: wrap; margin-left: auto; }}
  .legend-item {{ display: flex; align-items: center; gap: 4px; font-size: 0.75rem; color: #94a3b8;
                  border-radius: 12px; padding: 2px 8px 2px 4px; border: 1px solid transparent;
                  transition: opacity 0.2s, border-color 0.2s; user-select: none; }}
  .legend-item:hover {{ border-color: #475569; }}
  .legend-item.inactive {{ opacity: 0.35; }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}
  #canvas {{ width: 100%; height: calc(100vh - 105px); }}
  #tooltip {{ position: absolute; background: #1e293b; border: 1px solid #475569; border-radius: 8px;
              padding: 10px 14px; font-size: 0.8rem; pointer-events: none; display: none;
              box-shadow: 0 4px 24px #0008; max-width: 280px; }}
  #tooltip .pkg-name {{ font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-bottom: 4px; }}
  #tooltip .pkg-ver  {{ color: #94a3b8; margin-bottom: 6px; font-size: 0.78rem; }}
  #tooltip .pkg-type {{ display: inline-block; padding: 1px 8px; border-radius: 12px;
                        font-size: 0.7rem; font-weight: 600; }}
</style>
</head>
<body>
<div id="header">
  <h1>🔗 GMT SBOM Dependency Graph — {title}</h1>
  <div class="stats" id="stats"></div>
</div>
<div id="controls">
  <input type="text" id="search" placeholder="Paket suchen...">
  <label><input type="checkbox" id="hide-root" checked> Root-Edges ausblenden</label>
  <label><input type="checkbox" id="show-isolated"> Pakete ohne Deps zeigen</label>
  <div id="legend">{legend_items}</div>
</div>
<svg id="canvas"></svg>
<div id="tooltip"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script>
const ALL_NODES = {nodes_json};
const ALL_EDGES = {edges_json};

const svg = d3.select('#canvas');
const tooltip = document.getElementById('tooltip');
let width, height, sim, nodeEl, linkEl, labelEl;
let hiddenTypes = new Set();

function toggleType(el) {{
  const t = el.dataset.type;
  if (hiddenTypes.has(t)) {{
    hiddenTypes.delete(t);
    el.classList.remove('inactive');
  }} else {{
    hiddenTypes.add(t);
    el.classList.add('inactive');
  }}
  render();
}}

function getFilteredData() {{
  const hideRoot = document.getElementById('hide-root').checked;
  const showIsolated = document.getElementById('show-isolated').checked;
  const q = document.getElementById('search').value.toLowerCase();

  let edges = hideRoot ? ALL_EDGES.filter(e => !e.is_root_edge) : ALL_EDGES;
  const connected = new Set(edges.flatMap(e => [e.source, e.target]));

  let nodes = ALL_NODES.filter(n => {{
    if (q && !n.name.toLowerCase().includes(q)) return false;
    if (!showIsolated && !n.is_root && !connected.has(n.id)) return false;
    if (hideRoot && n.is_root) return false;
    if (hiddenTypes.has(n.type)) return false;
    return true;
  }});

  const nodeIds = new Set(nodes.map(n => n.id));
  edges = edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
  return {{ nodes, edges }};
}}

function render() {{
  svg.selectAll('*').remove();
  if (sim) sim.stop();

  width  = svg.node().clientWidth;
  height = svg.node().clientHeight;

  const {{ nodes, edges }} = getFilteredData();

  document.getElementById('stats').textContent =
    `${{nodes.length}} Pakete · ${{edges.length}} Abhängigkeiten`;

  const g = svg.append('g');

  // Zoom
  svg.call(d3.zoom().scaleExtent([0.1, 4]).on('zoom', e => g.attr('transform', e.transform)));

  // Defs (Pfeilspitzen)
  svg.append('defs').append('marker')
    .attr('id', 'arrow').attr('viewBox', '0 -4 8 8')
    .attr('refX', 18).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', '#475569');

  const nodeData = nodes.map(n => ({{ ...n }}));

  // simEdges: D3 mutiert source/target in-place zu Objekt-Referenzen beim ersten Tick.
  // linkEl und forceLink müssen dasselbe Array referenzieren, sonst bleibt d.source.x undefined.
  const simEdges = edges.map(e => ({{ source: e.source, target: e.target }}));

  linkEl = g.append('g').selectAll('line')
    .data(simEdges).join('line')
    .attr('stroke', '#475569').attr('stroke-width', 1.4)
    .attr('marker-end', 'url(#arrow)');

  nodeEl = g.append('g').selectAll('circle')
    .data(nodeData).join('circle')
    .attr('r', d => d.is_root ? 18 : 9)
    .attr('fill', d => d.color)
    .attr('stroke', '#0f172a').attr('stroke-width', 2)
    .style('cursor', 'pointer')
    .on('mouseover', (event, d) => {{
      tooltip.style.display = 'block';
      tooltip.innerHTML = `
        <div class="pkg-name">${{d.name}}</div>
        <div class="pkg-ver">${{d.version || '—'}}</div>
        <span class="pkg-type" style="background:${{d.color}}22;color:${{d.color}}">${{d.type}}</span>
      `;
    }})
    .on('mousemove', event => {{
      tooltip.style.left = (event.pageX + 14) + 'px';
      tooltip.style.top  = (event.pageY - 10) + 'px';
    }})
    .on('mouseout', () => {{ tooltip.style.display = 'none'; }})
    .call(d3.drag()
      .on('start', (e, d) => {{ if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
      .on('drag',  (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
      .on('end',   (e, d) => {{ if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }}));

  labelEl = g.append('g').selectAll('text')
    .data(nodeData).join('text')
    .text(d => d.name)
    .attr('font-size', d => d.is_root ? '11px' : '9px')
    .attr('fill', '#cbd5e1')
    .attr('text-anchor', 'middle')
    .attr('dy', d => d.is_root ? -22 : -13)
    .style('pointer-events', 'none');

  sim = d3.forceSimulation(nodeData)
    .force('link', d3.forceLink(simEdges).id(d => d.id).distance(80).strength(0.4))
    .force('charge', d3.forceManyBody().strength(-180))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(20))
    .on('tick', () => {{
      linkEl
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      nodeEl.attr('cx', d => d.x).attr('cy', d => d.y);
      labelEl.attr('x', d => d.x).attr('y', d => d.y);
    }});
}}

document.getElementById('hide-root').addEventListener('change', render);
document.getElementById('show-isolated').addEventListener('change', render);
document.getElementById('search').addEventListener('input', render);
window.addEventListener('resize', render);
render();
</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description='GMT SBOM Dependency Graph Visualizer')
    parser.add_argument('sbom', help='Pfad zur sbom.json')
    parser.add_argument('--output', '-o', default='sbom_graph.html', help='Ausgabe-HTML (Standard: sbom_graph.html)')
    parser.add_argument('--no-open', action='store_true', help='Browser nicht automatisch öffnen')
    args = parser.parse_args()

    sbom_path = Path(args.sbom)
    if not sbom_path.exists():
        print(f'Fehler: {sbom_path} nicht gefunden.')
        raise SystemExit(1)

    sbom = json.loads(sbom_path.read_text(encoding='utf-8'))
    nodes, edges = build_graph(sbom)
    html = generate_html(nodes, edges, title=sbom_path.stem)

    out_path = Path(args.output)
    out_path.write_text(html, encoding='utf-8')
    print(f'Graph geschrieben: {out_path}')
    print(f'Knoten: {len(nodes)}  Kanten: {len(edges)}')

    if not args.no_open:
        webbrowser.open(out_path.resolve().as_uri())


if __name__ == '__main__':
    main()
