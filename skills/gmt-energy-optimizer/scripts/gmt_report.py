#!/usr/bin/env python3
"""
gmt_report.py - renders a self-contained HTML report from a bundle and the skill's findings.

    python gmt_report.py --bundle bundle.json --findings findings.json --out report.html

No JavaScript and no external resources: charts are inline SVG, so the page works offline and
can be embedded (e.g. in the GMT frontend). Light and dark mode follow the OS setting.
"""

import argparse
import html
import json
from pathlib import Path

CRIT = {  # GMT criticality colors -> label
    "red": "High", "orange": "Medium", "yellow": "Low", "green": "Good", "blue": "Info",
}
CRIT_ORDER = ["red", "orange", "yellow", "blue", "green"]
SERIES = ["var(--s1)", "var(--s2)", "var(--s3)", "var(--s4)", "var(--s5)"]


def esc(x):
    return html.escape(str(x)) if x is not None else ""


def fmt_j(v):
    if v is None:
        return "-"
    v = float(v)
    if abs(v) >= 1000:
        return f"{v/1000:.1f} kJ"
    return f"{v:.0f} J"


def fmt_s(v):
    if v is None:
        return "-"
    v = float(v)
    return f"{v/60:.1f} min" if v >= 120 else f"{v:.0f} s"


def short(name, n=34):
    return name if len(name) <= n else name[: n - 1] + "…"


# ----------------------------------------------------------------------------
# SVG helpers
# ----------------------------------------------------------------------------

def hbar_stacked(rows, width=720, label_w=230, row_h=26, value_fmt=fmt_j, legend=None):
    """rows: [(label, [(value, color, title)], right_text)]"""
    maxv = max((sum(v for v, _, _ in segs) for _, segs, _ in rows), default=1) or 1
    plot_w = width - label_w - 110
    h = row_h * len(rows) + 8
    out = [f'<svg viewBox="0 0 {width} {h}" class="chart" role="img">']
    for i, (label, segs, right) in enumerate(rows):
        y = 4 + i * row_h
        out.append(f'<text x="{label_w - 8}" y="{y + row_h/2 + 4}" text-anchor="end" class="lbl">{esc(short(label))}</text>')
        x = label_w
        for v, color, title in segs:
            w = max(plot_w * v / maxv, 0)
            if w > 0:
                out.append(f'<rect x="{x:.1f}" y="{y + 4}" width="{w:.1f}" height="{row_h - 8}" rx="2" fill="{color}"><title>{esc(title)}</title></rect>')
            x += w
        out.append(f'<text x="{x + 6:.1f}" y="{y + row_h/2 + 4}" class="val">{esc(right)}</text>')
    out.append("</svg>")
    leg = ""
    if legend:
        leg = '<div class="legend">' + "".join(
            f'<span><i style="background:{c}"></i>{esc(t)}</span>' for t, c in legend) + "</div>"
    return "".join(out) + leg


def grouped_bars(groups, series_names, width=720, label_w=230, bar_h=12, gap=10):
    """groups: [(label, [value per series or None])] - horizontal grouped bars"""
    n = len(series_names)
    maxv = max((v for _, vals in groups for v in vals if v), default=1) or 1
    plot_w = width - label_w - 90
    gh = n * bar_h + gap
    h = gh * len(groups) + 6
    out = [f'<svg viewBox="0 0 {width} {h}" class="chart" role="img">']
    for gi, (label, vals) in enumerate(groups):
        y0 = 3 + gi * gh
        out.append(f'<text x="{label_w - 8}" y="{y0 + n*bar_h/2 + 4}" text-anchor="end" class="lbl">{esc(short(label))}</text>')
        for si, v in enumerate(vals):
            y = y0 + si * bar_h
            if v is None:
                continue
            w = plot_w * v / maxv
            out.append(f'<rect x="{label_w}" y="{y + 1}" width="{max(w, 0.5):.1f}" height="{bar_h - 2}" rx="2" fill="{SERIES[si % len(SERIES)]}"><title>{esc(series_names[si])}: {fmt_j(v)}</title></rect>')
            out.append(f'<text x="{label_w + w + 5:.1f}" y="{y + bar_h - 2}" class="val sm">{fmt_j(v)}</text>')
    out.append("</svg>")
    leg = '<div class="legend">' + "".join(
        f'<span><i style="background:{SERIES[i % len(SERIES)]}"></i>{esc(s)}</span>' for i, s in enumerate(series_names)) + "</div>"
    return "".join(out) + leg


def simple_bars(items, highlight=None, width=720, label_w=230, row_h=24, fmt=lambda v: f"{v:g}"):
    maxv = max((v for _, v in items), default=1) or 1
    plot_w = width - label_w - 110
    h = row_h * len(items) + 6
    out = [f'<svg viewBox="0 0 {width} {h}" class="chart" role="img">']
    for i, (label, v) in enumerate(items):
        y = 3 + i * row_h
        color = "var(--accent)" if label == highlight else "var(--muted-bar)"
        w = plot_w * v / maxv
        weight = ' font-weight="600"' if label == highlight else ""
        out.append(f'<text x="{label_w - 8}" y="{y + row_h/2 + 4}" text-anchor="end" class="lbl"{weight}>{esc(label)}</text>')
        out.append(f'<rect x="{label_w}" y="{y + 4}" width="{max(w, 0.5):.1f}" height="{row_h - 8}" rx="2" fill="{color}"/>')
        out.append(f'<text x="{label_w + w + 6:.1f}" y="{y + row_h/2 + 4}" class="val">{esc(fmt(v))}</text>')
    out.append("</svg>")
    return "".join(out)


# ----------------------------------------------------------------------------
# sections
# ----------------------------------------------------------------------------

def section_header(b):
    run, m, dq, rep = b["run"], b["machine"], b["data_quality"], b.get("repetitions") or {}
    e = b["energy"]
    tier = ((b.get("configuration_tiers") or {}).get("this_run") or {}).get("tier")
    chips = [
        f'{e.get("total_energy_j") and fmt_j(e["total_energy_j"])} total',
        f'{fmt_j(e.get("total_attributable_energy_j"))} attributable',
        f'baseline {e.get("baseline_power_w")} W',
        f'scope {dq.get("energy_scope")}',
    ]
    if rep:
        chips.append(f'{rep.get("n_total_including_this_run")} repetitions · noise {rep.get("effective_noise_pct")} %')
    if tier:
        chips.append(f"config tier {tier}")
    link = f'https://metrics.green-coding.io/stats.html?id={run["run_id"]}'
    return f"""
<header>
  <p class="eyebrow">GMT energy optimizer · report</p>
  <h1>{esc(run.get("name"))}</h1>
  <p class="meta">{esc(m.get("Hardware Model"))} · {esc(m.get("Cpu Info"))} · {esc(m.get("Operating System"))}
     · run <a href="{link}">{esc(run["run_id"][:8])}</a> · {esc(str(run.get("created_at"))[:10])}</p>
  <div class="chips">{"".join(f"<span>{esc(c)}</span>" for c in chips)}</div>
</header>"""


def saving_text(es):
    if not es:
        return ""
    basis = es.get("basis")
    v, lo, hi = es.get("value"), es.get("min"), es.get("max")
    tgt = "CO₂" if es.get("target") == "co2" else "energy"
    if basis in ("measured", "computed", "energy_id") and v is not None:
        return f"{v:+g} % {tgt}"
    if lo is not None and hi is not None and lo != hi:
        a_, b_ = sorted([lo, hi], key=abs)
        return f"{a_:+.0f} … {b_:+.0f} % {tgt}"
    if hi is not None:
        return f"up to {hi:+g} % {tgt}"
    return "saving unknown"


def section_findings(findings):
    fs = sorted(findings, key=lambda f: CRIT_ORDER.index(f.get("criticality", "blue")) if f.get("criticality") in CRIT_ORDER else 9)
    cards = []
    for f in fs:
        crit = f.get("criticality", "blue")
        es = f.get("estimated_saving") or {}
        ev = "".join(
            f"<li><b>{esc(x.get('metric'))}</b> ({esc(x.get('phase') or '-')}): {esc(x.get('value'))} {esc(x.get('unit'))}</li>"
            for x in f.get("evidence") or [])
        link = f'<a href="{esc(f["link"])}">source</a>' if f.get("link") else ""
        cards.append(f"""
<article class="card c-{crit}">
  <div class="card-top">
    <span class="badge b-{crit}">{CRIT.get(crit, crit)}</span>
    <span class="saving">{esc(saving_text(es))}</span>
  </div>
  <h3>{esc(f.get("title"))}</h3>
  <p>{esc(f.get("description"))}</p>
  <div class="tags"><span>basis: {esc(es.get("basis"))}</span><span>confidence: {esc(f.get("confidence"))}</span>
    <span>effort: {esc(f.get("effort"))}</span><span>lever: {esc(f.get("lever"))}</span>{link}</div>
  <details><summary>Evidence & how to verify</summary><ul>{ev}</ul><p class="verify">{esc(f.get("verify"))}</p></details>
</article>""")
    return f'<section><h2>Recommendations</h2><div class="cards">{"".join(cards)}</div></section>'


def section_energy(b):
    ph = b["energy"]["phases"]
    order = ["[INSTALLATION]", "[BOOT]", "[IDLE]"] + [k for k, v in ph.items() if v.get("is_flow")] + ["[REMOVE]"]
    rows = []
    for name in order:
        p = ph.get(name)
        if not p or p.get("energy_j") is None:
            continue
        e, a = p["energy_j"], p.get("attributable_energy_j") or 0
        base = max(e - a, 0)
        label = ("  ↳ " + name) if p.get("is_flow") else name
        rows.append((label, [(base, "var(--base)", f"base load {fmt_j(base)}"),
                             (a, "var(--accent)", f"attributable {fmt_j(a)}")],
                     f"{fmt_j(e)} · {fmt_s(p.get('duration_s'))}"))
    chart = hbar_stacked(rows, legend=[("machine base load", "var(--base)"), ("attributable to the software", "var(--accent)")])
    return f"""<section><h2>Where the energy goes</h2>
<p class="hint">Each phase split into the machine's base load ({b['energy'].get('baseline_power_w')} W × duration) and the energy
caused by the software. Flow steps (↳) are part of [RUNTIME].</p>{chart}</section>"""


def section_alternatives(b):
    alts = [a for a in ((b.get("energy_id") or {}).get("alternatives_by_software") or []) if a.get("phase_comparison")]
    if not alts:
        return ""
    alts = alts[:3]
    names = ["this run"] + [a["software"] for a in alts]
    phases = [p["phase"] for p in alts[0]["phase_comparison"] if p["phase"] not in ("[REMOVE]", "[IDLE]")]
    groups = []
    for ph in phases:
        vals = [next((p["this_run_energy_j"] for p in alts[0]["phase_comparison"] if p["phase"] == ph), None)]
        for a in alts:
            vals.append(next((p["other_energy_j"] for p in a["phase_comparison"] if p["phase"] == ph), None))
        groups.append((ph, vals))
    noise = (b.get("energy_id") or {}).get("noise_threshold_pct")
    return f"""<section><h2>Same task, other software</h2>
<p class="hint">Energy ID measurements of the same scenario on the same machine, phase by phase. Shows <i>where</i> a difference
comes from. Noise threshold for this scenario: {noise} %.</p>{grouped_bars(groups, names)}</section>"""


def section_j_per_unit(b):
    ct = b.get("configuration_tiers") or {}
    ju = ct.get("j_per_unit_t3_all_dbms") or {}
    if not ju:
        return ""
    own = (b.get("cross_benchmark") or {}).get("dbms")
    items = [(k, v["t3_j_per_unit"]) for k, v in ju.items()]
    bench = ct.get("benchmark_dbms", "").split("/")[0]
    return f"""<section><h2>Energy per unit of work · {esc(bench)}</h2>
<p class="hint">Each DBMS at its energy-optimal configuration (tier T3). Lower is better. For time-boxed benchmarks this,
not energy per time, shows efficiency.</p>{simple_bars(items, highlight=own, fmt=lambda v: f"{v:g} J/unit")}</section>"""


def section_tiers(b):
    ct = b.get("configuration_tiers") or {}
    mt = (ct.get("measured_tiers") or {}).get("tiers") or {}
    if not mt:
        return ""
    desc = ct.get("descriptions") or {}
    tiers = sorted(mt)
    def tier_label(t):
        d = desc.get(t, "").split(":")[-1].strip()
        return f"{t} · {d.split(',')[0].replace('configuration per cell', '').replace('the configuration as ', '').strip()}"
    groups = [(tier_label(t), [mt[t].get("load_energy_j"), mt[t].get("workload_energy_j")]) for t in tiers]
    knobs = ((ct.get("measured_tiers") or {}).get("t3_cell") or {}).get("t3_changes_vs_t2") or []
    def num(v):
        try:
            f = float(v)
            return f"{f:.3g}" if "." in str(v) and len(str(v)) > 6 else v
        except (TypeError, ValueError):
            return v
    rows = "".join(f"<tr><td>{esc(k['parameter'])}</td><td>{esc(num(k['t2']))}</td><td>{esc(num(k['t3']))}</td></tr>" for k in knobs)
    table = f'<table><thead><tr><th>Parameter</th><th>T2</th><th>T3 (energy-optimal)</th></tr></thead><tbody>{rows}</tbody></table>' if rows else ""
    this = (ct.get("this_run") or {})
    return f"""<section><h2>Server configuration tiers · {esc(ct.get("benchmark_dbms"))}</h2>
<p class="hint">Same schema, data and clients; only server parameters differ. This run: <b>{esc(this.get("tier"))}</b>
({esc(this.get("source"))}).</p>{grouped_bars(groups, ["load", "workload"])}{table}</section>"""


def section_cross(b):
    cb = b.get("cross_benchmark") or {}
    fac = cb.get("factors") or {}
    if not fac:
        return ""
    benches = sorted({k for f in fac.values() for k in (f.get("per_benchmark_geomean") or {})})
    def cell(v):
        if v is None:
            return "<td>-</td>"
        cls = "hi" if v > 1.05 else "lo" if v < 0.95 else ""
        return f'<td class="{cls}">{v:.2f}×</td>'
    rows = "".join(
        f"<tr><th>{cls}</th>{''.join(cell((fac[cls].get('per_benchmark_geomean') or {}).get(bn)) for bn in benches)}</tr>"
        for cls in ("load", "workload", "runtime") if cls in fac)
    wt = cb.get("workload_type") or {}
    types = {bn: next((v for k, v in wt.items() if k.split("@")[0] == bn), "") for bn in benches}
    head = "".join(f"<th>{esc(bn)}<br><small>{esc(types[bn].replace('_', ' '))}</small></th>" for bn in benches)
    return f"""<section><h2>{esc(cb.get("dbms"))} across benchmarks</h2>
<p class="hint">Energy relative to the median DBMS of each benchmark (1.00× = typical). Red = more energy, green = less.
A pattern in several benchmarks is a property of the DBMS, not of one scenario.</p>
<table class="heat"><thead><tr><th></th>{head}</tr></thead><tbody>{rows}</tbody></table></section>"""


CSS = """
:root{--bg:#fff;--fg:#1d2329;--muted:#5f6b76;--line:#e3e7eb;--card:#f7f9fa;--accent:#2f7d6d;--base:#c9d1d8;
--muted-bar:#9fb0bd;--s1:#2f7d6d;--s2:#4a78c2;--s3:#d08a2e;--s4:#8a63b8;--s5:#c25a5a;
--red:#c43d3d;--orange:#d9822b;--yellow:#c9a227;--green:#3f9b5a;--blue:#3b7bc4;--hi:#f6dada;--lo:#d9efe0}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#14181c;--fg:#e6eaee;--muted:#9aa6b1;--line:#2a3138;
--card:#1b2126;--accent:#4fb39d;--base:#3a444d;--muted-bar:#5d6c78;--s1:#4fb39d;--s2:#6f9be0;--s3:#e0a556;--s4:#a988d4;--s5:#e07c7c;
--hi:#4a2626;--lo:#1f3d2a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:28px 16px 60px}
a{color:var(--accent)}h1{font-size:26px;margin:4px 0 6px}h2{font-size:18px;margin:36px 0 8px}h3{font-size:16px;margin:8px 0 6px}
.eyebrow{margin:0;color:var(--muted);font-size:12px;letter-spacing:.06em;text-transform:uppercase}
.meta,.hint{color:var(--muted);font-size:13px;margin:0 0 10px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}.chips span{border:1px solid var(--line);border-radius:999px;padding:2px 10px;font-size:12.5px}
.cards{display:grid;gap:12px}.card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:8px;padding:12px 14px}
.c-red{border-left-color:var(--red)}.c-orange{border-left-color:var(--orange)}.c-yellow{border-left-color:var(--yellow)}.c-green{border-left-color:var(--green)}
.card p{margin:4px 0 8px}.card-top{display:flex;justify-content:space-between;align-items:center;gap:8px}
.badge{font-size:11.5px;font-weight:600;color:#fff;border-radius:4px;padding:1px 7px}
.b-red{background:var(--red)}.b-orange{background:var(--orange)}.b-yellow{background:var(--yellow)}.b-green{background:var(--green)}.b-blue{background:var(--blue)}
.saving{font-weight:600;font-variant-numeric:tabular-nums}
.tags{display:flex;flex-wrap:wrap;gap:6px;font-size:12px;color:var(--muted)}.tags span{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:0 6px}
details{margin-top:8px;font-size:13px}summary{cursor:pointer;color:var(--muted)}details ul{margin:6px 0;padding-left:18px}.verify{color:var(--muted)}
.chart{width:100%;height:auto;display:block;margin:6px 0}.chart .lbl{fill:var(--fg);font-size:12px}.chart .val{fill:var(--muted);font-size:11.5px}.chart .sm{font-size:10.5px}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted)}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
table{border-collapse:collapse;width:100%;margin-top:10px;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left}
.heat td{text-align:center;font-variant-numeric:tabular-nums}.heat td.hi{background:var(--hi)}.heat td.lo{background:var(--lo)}
footer{margin-top:40px;color:var(--muted);font-size:12px}
@media (max-width:600px){h1{font-size:21px}.chart .lbl{font-size:13px}}
"""


def render(bundle, findings):
    run = bundle["run"]
    body = "".join([
        section_header(bundle),
        section_findings(findings),
        section_energy(bundle),
        section_alternatives(bundle),
        section_j_per_unit(bundle),
        section_tiers(bundle),
        section_cross(bundle),
    ])
    foot = (f"bundle v{esc(bundle.get('bundle_version'))} · Energy ID digest "
            f"{esc((bundle.get('energy_id') or {}).get('digest_generated_at'))} · numbers computed by gmt_bundle.py, "
            f"recommendations by the gmt-energy-optimizer skill")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Energy report · {esc(short(run.get('name') or run['run_id'], 40))}</title><style>{CSS}</style></head>
<body><main>{body}<footer>{foot}</footer></main></body></html>"""


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bundle", required=True)
    p.add_argument("--findings", required=True)
    p.add_argument("--out", default="report.html")
    a = p.parse_args()
    bundle = json.loads(Path(a.bundle).read_text(encoding="utf-8"))
    findings = json.loads(Path(a.findings).read_text(encoding="utf-8"))
    Path(a.out).write_text(render(bundle, findings), encoding="utf-8")
    print(f"report -> {a.out}")


if __name__ == "__main__":
    main()
