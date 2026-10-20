#!/usr/bin/env python3
"""
gmt_bundle.py - prepares compact, pre-computed input for the gmt-energy-optimizer skill.

Two stages:

  1) digest  - crawl Energy ID once (or weekly) and compress every task into one row,
               plus per-category distributions of hardware-independent shape metrics.
               python gmt_bundle.py digest --out energy_id_digest.json

  2) run     - analyse one GMT run and attach only the relevant slice of the digest
               (same task measured for other software + category peer stats).
               python gmt_bundle.py run <run_id> --digest energy_id_digest.json --out bundle.json

All numbers the agent may quote are computed here. The LLM only interprets them.

Units in the output: energy J, power W, duration s, data bytes, carbon g CO2e,
CPU utilization percent (0-100), memory bytes.
"""

import argparse
import json
import re
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

API = "https://api.green-coding.io"

STANDARD_PHASES = ["[BASELINE]", "[INSTALLATION]", "[BOOT]", "[IDLE]", "[RUNTIME]", "[REMOVE]"]

# Priority for the "primary" energy metric. Scope must be identical when comparing two runs.
ENERGY_PRIORITY = [
    ("psu_ac", re.compile(r"^psu_energy_ac_.*_machine$")),
    ("psu_dc_rapl", re.compile(r"^psu_energy_dc_rapl_msr_machine$")),
    ("rapl_cpu_mem", None),  # cpu_energy_rapl_* + memory_energy_rapl_* (summed)
]

SPEC_KEYS = [
    "Cpu Info", "Memory Total", "Operating System", "Kernel Version", "Architecture",
    "Hardware Model", "Scaling Governor", "Hyper Threading", "Turbo Boost (1=off)",
    "Virtualization", "Docker Virtual Machine",
]

IDLE_CPU_PCT = 5.0  # CALIBRATE: below this mean CPU utilization a phase counts as "mostly idle"


# ----------------------------------------------------------------------------
# API access with on-disk cache
# ----------------------------------------------------------------------------

class Api:
    def __init__(self, cache_dir: Path, pause: float = 0.2, refresh: bool = False):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.pause = pause
        self.refresh = refresh
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "htw-caso-gmt-bundle/0.1"

    def get(self, path, params=None):
        key = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.strip("/"))
        if params:
            key += "_" + re.sub(r"[^A-Za-z0-9_.-]+", "_", json.dumps(params, sort_keys=True))
        cache = self.cache_dir / f"{key[:200]}.json"
        if cache.exists() and not self.refresh:
            return json.loads(cache.read_text(encoding="utf-8"))
        r = self.s.get(API + path, params=params, timeout=90)
        time.sleep(self.pause)
        if r.status_code == 204:
            data = None
        elif r.status_code in (403, 404, 410, 422):
            data = None
        else:
            r.raise_for_status()
            data = r.json().get("data")
        cache.write_text(json.dumps(data), encoding="utf-8")
        return data


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

def r(x, nd=2):
    return None if x is None else round(float(x), nd)


def pct(part, whole):
    if part is None or not whole:
        return None
    return round(100.0 * part / whole, 1)


def mem_to_bytes(v):
    """docker style '2g', '512m', '1024' -> bytes"""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    m = re.match(r"^\s*([\d.]+)\s*([kmgt]?)b?\s*$", str(v).lower())
    if not m:
        return None
    mult = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}[m.group(2)]
    return float(m.group(1)) * mult


def quantiles(values):
    v = sorted(x for x in values if x is not None)
    if not v:
        return None
    if len(v) == 1:
        return {"n": 1, "p25": r(v[0], 1), "median": r(v[0], 1), "p75": r(v[0], 1)}
    q = statistics.quantiles(v, n=4, method="inclusive")
    return {"n": len(v), "p25": r(q[0], 1), "median": r(q[1], 1), "p75": r(q[2], 1)}


def stat_value(detail_obj):
    """phase_stats detail -> {mean,max,min} of the single run inside"""
    data = detail_obj.get("data") or {}
    if not data:
        return None
    first = next(iter(data.values()))
    return first


def metric_sum(phase_obj, metric, field="mean"):
    m = (phase_obj.get("data") or {}).get(metric)
    if not m:
        return None, None
    total, found = 0.0, False
    for det in (m.get("data") or {}).values():
        v = stat_value(det)
        if v and v.get(field) is not None:
            total += float(v[field])
            found = True
    return (total if found else None), m.get("unit")


def metric_by_detail(phase_obj, metric, field="mean"):
    m = (phase_obj.get("data") or {}).get(metric)
    if not m:
        return {}, None
    out = {}
    for name, det in (m.get("data") or {}).items():
        v = stat_value(det)
        if v and v.get(field) is not None:
            out[name] = float(v[field])
    return out, m.get("unit")


# ----------------------------------------------------------------------------
# core: one run -> compact summary   (used for the analysed run AND the digest)
# ----------------------------------------------------------------------------

def choose_energy_scope(phase_stats):
    """pick one energy scope that is present in [RUNTIME]; return (scope, metric list)"""
    runtime = (phase_stats.get("data") or {}).get("[RUNTIME]") or {}
    metrics = list((runtime.get("data") or {}).keys())
    for scope, rx in ENERGY_PRIORITY:
        if rx is None:
            rapl = [m for m in metrics if re.match(r"^(cpu|memory)_energy_rapl_.*_component$", m)]
            if rapl:
                return scope, sorted(rapl)
        else:
            hits = [m for m in metrics if rx.match(m)]
            if hits:
                return scope, [sorted(hits)[0]]
    return None, []


def phase_energy_j(phase_obj, energy_metrics):
    total, found = 0.0, False
    for m in energy_metrics:
        v, unit = metric_sum(phase_obj, m)
        if v is None:
            continue
        if unit != "uJ":
            raise ValueError(f"unexpected energy unit {unit} for {m}")
        total += v / 1e6
        found = True
    return total if found else None


def summarize_run(run, phase_stats):
    durations = {}
    for p in run.get("phases") or []:
        if p.get("start") is not None and p.get("end") is not None:
            durations[p["name"]] = (p["end"] - p["start"]) / 1e6

    scope, energy_metrics = choose_energy_scope(phase_stats or {})
    pdata = (phase_stats or {}).get("data") or {}

    phases = {}
    for name, pobj in pdata.items():
        d = durations.get(name)
        e = phase_energy_j(pobj, energy_metrics) if energy_metrics else None
        cpu_sys, _ = metric_sum(pobj, "cpu_utilization_procfs_system")
        cpu_ctr, _ = metric_by_detail(pobj, "cpu_utilization_cgroup_container")
        mem_ctr_mean, _ = metric_by_detail(pobj, "memory_used_cgroup_container", "mean")
        mem_ctr_max, _ = metric_by_detail(pobj, "memory_used_cgroup_container", "max")
        net, _ = metric_sum(pobj, "network_total_cgroup_container")
        if net is None:
            net, _ = metric_sum(pobj, "network_total_procfs_system")
        disk_r, _ = metric_sum(pobj, "disk_total_read_procfs_system")
        disk_w, _ = metric_sum(pobj, "disk_total_write_procfs_system")
        carbon = None
        for m in (pobj.get("data") or {}):
            if "_carbon_" in m and m.endswith("_machine"):
                v, unit = metric_sum(pobj, m)
                if v is not None and unit == "ugCO2e":
                    carbon = (carbon or 0) + v / 1e6
        ci, _ = metric_sum(pobj, "carbon_intensity_static_machine")
        if ci is None:
            ci, _ = metric_sum(pobj, "carbon_intensity_electricity_maps_machine")

        phases[name] = {
            "hidden": pobj.get("hidden"),
            "is_flow": name not in STANDARD_PHASES,
            "duration_s": r(d),
            "energy_j": r(e),
            "power_w": r(e / d) if e is not None and d else None,
            # GMT stores utilization as 'Ratio' = percent * 100
            "cpu_util_system_pct": r(cpu_sys / 100, 1) if cpu_sys is not None else None,
            "cpu_util_container_pct": {k: r(v / 100, 1) for k, v in cpu_ctr.items()} or None,
            "mem_container_mean_bytes": {k: int(v) for k, v in mem_ctr_mean.items()} or None,
            "mem_container_max_bytes": {k: int(v) for k, v in mem_ctr_max.items()} or None,
            "network_bytes": int(net) if net is not None else None,
            "disk_read_bytes": int(disk_r) if disk_r is not None else None,
            "disk_write_bytes": int(disk_w) if disk_w is not None else None,
            "carbon_g": r(carbon, 4),
            "carbon_intensity_g_per_kwh": r(ci, 1),
        }

    # baseline subtraction and shares (top-level phases only; flow phases are inside [RUNTIME])
    base = phases.get("[BASELINE]") or {}
    base_p = base.get("power_w")
    top = [p for p in STANDARD_PHASES if p in phases and p != "[BASELINE]"]
    total_e = sum(phases[p]["energy_j"] or 0 for p in top) or None
    total_attr = 0.0
    for name, ph in phases.items():
        if ph["energy_j"] is not None and base_p is not None and ph["duration_s"]:
            ph["attributable_energy_j"] = r(max(ph["energy_j"] - base_p * ph["duration_s"], 0.0))
        else:
            ph["attributable_energy_j"] = None
        if name in top:
            ph["share_of_total_pct"] = pct(ph["energy_j"], total_e)
            total_attr += ph["attributable_energy_j"] or 0
    rt_e = (phases.get("[RUNTIME]") or {}).get("energy_j")
    for name, ph in phases.items():
        if ph["is_flow"]:
            ph["share_of_runtime_pct"] = pct(ph["energy_j"], rt_e)
        cpu = ph["cpu_util_system_pct"]
        ph["mostly_idle"] = (cpu is not None and cpu < IDLE_CPU_PCT)

    # hardware-independent shape metrics (for peer comparison)
    def share(p):
        return (phases.get(p) or {}).get("share_of_total_pct")
    rt = phases.get("[RUNTIME]") or {}
    flow = [ph for ph in phases.values() if ph["is_flow"] and ph["duration_s"]]
    idle_flow_time = sum(ph["duration_s"] for ph in flow if ph["mostly_idle"])
    flow_time = sum(ph["duration_s"] for ph in flow)
    shape = {
        "installation_share_pct": share("[INSTALLATION]"),
        "boot_share_pct": share("[BOOT]"),
        "idle_phase_share_pct": share("[IDLE]"),
        "runtime_share_pct": share("[RUNTIME]"),
        "runtime_power_vs_baseline": r(rt.get("power_w") / base_p, 2) if rt.get("power_w") and base_p else None,
        "runtime_cpu_util_pct": rt.get("cpu_util_system_pct"),
        "idle_time_in_flow_pct": pct(idle_flow_time, flow_time),
    }

    return {
        "energy_scope": scope,
        "energy_metrics": energy_metrics,
        "baseline_power_w": base_p,
        "total_energy_j": r(total_e),
        "total_attributable_energy_j": r(total_attr) if base_p is not None else None,
        "phases": phases,
        "shape": shape,
    }


def machine_summary(run):
    specs = run.get("machine_specs") or {}
    out = {"machine_id": run.get("machine_id")}
    for k in SPEC_KEYS:
        v = specs.get(k)
        if v not in (None, ""):
            out[k] = str(v).strip()[:120]
    return out


def container_summary(run):
    out = {}
    for name, c in (run.get("containers") or {}).items():
        out[name] = {
            "image": c.get("image"),
            "cpus": c.get("cpus"),
            "mem_limit_bytes": mem_to_bytes(c.get("mem_limit")),
        }
    return out


# ----------------------------------------------------------------------------
# stage 1: digest
# ----------------------------------------------------------------------------

def cmd_digest(args):
    api = Api(Path(args.cache), args.pause, args.refresh)
    softwares, page = [], 1
    while True:
        data = api.get("/v1/software", {"page": page})
        if not data:
            break
        softwares += data
        if len(data) < 50:
            break
        page += 1
    print(f"software entries: {len(softwares)}", file=sys.stderr)

    tasks, run_cache = [], {}
    for i, sw in enumerate(softwares, 1):
        for t in api.get(f"/v1/software/{sw['id']}/tasks") or []:
            rid = t.get("run_id")
            row = {
                "software_id": sw["id"], "software": sw["name"],
                "categories": [c.strip() for c in (sw.get("categories") or "").split(",") if c.strip()],
                "task": t["name"], "phase": t["phase"],
                "machine_id": t["machine_id"], "machine": t["machine_name"],
                "uri": t["uri"], "filename": t["filename"], "run_id": rid,
            }
            if rid:
                if rid not in run_cache:
                    run = api.get(f"/v2/run/{rid}") or {}
                    stats = api.get(f"/v1/phase_stats/single/{rid}") or {}
                    try:
                        run_cache[rid] = summarize_run(run, stats)
                    except Exception as exc:  # keep crawling, record the problem
                        run_cache[rid] = {"error": str(exc)}
                s = run_cache[rid]
                ph = (s.get("phases") or {}).get(t["phase"]) or {}
                row.update({
                    "energy_scope": s.get("energy_scope"),
                    "energy_j": ph.get("energy_j"),
                    "attributable_energy_j": ph.get("attributable_energy_j"),
                    "duration_s": ph.get("duration_s"),
                    "power_w": ph.get("power_w"),
                    "cpu_util_system_pct": ph.get("cpu_util_system_pct"),
                    "network_bytes": ph.get("network_bytes"),
                    "shape": s.get("shape"),
                    "error": s.get("error"),
                })
            tasks.append(row)
        print(f"  [{i}/{len(softwares)}] {sw['name']}", file=sys.stderr)

    # per-category peer distributions (one value per run, not per task)
    per_cat = defaultdict(lambda: defaultdict(dict))
    for t in tasks:
        if not t.get("shape"):
            continue
        for c in t["categories"] or ["(none)"]:
            per_cat[c][t["run_id"]] = t["shape"]
    categories = {}
    for c, runs in per_cat.items():
        shapes = list(runs.values())
        categories[c] = {
            k: quantiles([s.get(k) for s in shapes])
            for k in shapes[0].keys()
        }

    digest = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": API,
        "n_software": len(softwares),
        "n_tasks": len(tasks),
        "tasks": tasks,
        "category_shape_stats": categories,
    }
    Path(args.out).write_text(json.dumps(digest, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"digest -> {args.out} ({len(tasks)} tasks, {len(categories)} categories)", file=sys.stderr)


# ----------------------------------------------------------------------------
# stage 2: run bundle
# ----------------------------------------------------------------------------

def cmd_run(args):
    api = Api(Path(args.cache), args.pause, args.refresh)
    rid = args.run_id
    run = api.get(f"/v2/run/{rid}")
    if not run:
        sys.exit(f"run {rid} not found or not public")
    stats = api.get(f"/v1/phase_stats/single/{rid}") or {}
    summary = summarize_run(run, stats)

    # data quality
    warnings = api.get(f"/v1/warnings/{rid}") or []
    reps = api.get("/v2/runs", {
        "uri": run.get("uri"), "uri_mode": "exact", "filename": run.get("filename"),
        "machine_id": run.get("machine_id"), "failed": False, "limit": 50,
    }) or []
    gmt_opts = api.get(f"/v1/optimizations/{rid}") or []

    bundle = {
        "bundle_version": "0.1",
        "run": {
            "run_id": rid, "name": run.get("name"), "uri": run.get("uri"),
            "branch": run.get("branch"), "filename": run.get("filename"),
            "commit_hash": run.get("commit_hash"), "created_at": run.get("created_at"),
            "categories": run.get("categories"),
            "usage_scenario_variables": run.get("usage_scenario_variables"),
            "failed": run.get("failed"),
        },
        "machine": machine_summary(run),
        "containers": container_summary(run),
        "data_quality": {
            "failed": bool(run.get("failed")),
            "warnings": [str(w)[:200] for w in warnings][:15],
            "energy_scope": summary["energy_scope"],
            "energy_metrics": summary["energy_metrics"],
            "has_baseline": summary["baseline_power_w"] is not None,
            "repetitions_same_scenario_same_machine": len(reps),
            "repetition_run_ids": [row[0] for row in reps][:20],
        },
        "energy": summary,
        "gmt_existing_optimizations": [
            {"title": o[0], "label": o[1], "criticality": o[2], "reporter": o[3]} for o in gmt_opts
        ],
        "energy_id": None,
    }

    if args.digest:
        digest = json.loads(Path(args.digest).read_text(encoding="utf-8"))
        own = [t for t in digest["tasks"]
               if t["uri"] == run.get("uri") and t["filename"] == run.get("filename")]
        own_by_task = {(t["task"], t["machine_id"]): t for t in own}
        task_names = sorted({t["task"] for t in own})
        cats = sorted({c for t in own for c in t["categories"]} |
                      {c.strip() for c in (run.get("categories") or "").split(",") if c.strip()})

        alternatives = []
        for name in task_names:
            # reference value of THIS run for the task (same phase), measured in this run
            own_t = next((t for t in own if t["task"] == name), None)
            own_phase = (summary["phases"].get(own_t["phase"]) or {}) if own_t else {}
            for t in digest["tasks"]:
                if t["task"] != name or t["uri"] == run.get("uri") or t.get("energy_j") is None:
                    continue
                same_machine = t["machine_id"] == run.get("machine_id")
                same_scope = t.get("energy_scope") == summary["energy_scope"]
                delta = None
                if same_machine and same_scope and own_phase.get("energy_j"):
                    delta = pct(t["energy_j"] - own_phase["energy_j"], own_phase["energy_j"])
                alternatives.append({
                    "task": name, "phase": t["phase"], "software": t["software"],
                    "machine_id": t["machine_id"], "machine": t["machine"],
                    "energy_j": t["energy_j"], "duration_s": t["duration_s"], "power_w": t["power_w"],
                    "run_id": t["run_id"],
                    "this_run_energy_j": own_phase.get("energy_j"),
                    "delta_vs_this_run_pct": delta,
                    "comparable": same_machine and same_scope,
                    "note": None if (same_machine and same_scope)
                    else "different machine or energy scope - indicative only, use ratios not absolutes",
                })
        alternatives.sort(key=lambda a: (not a["comparable"], a["delta_vs_this_run_pct"] if a["delta_vs_this_run_pct"] is not None else 1e9))

        bundle["energy_id"] = {
            "digest_generated_at": digest.get("generated_at"),
            "matched_tasks": task_names,
            "alternatives": alternatives[: args.max_alternatives],
            "category_peer_stats": {c: digest["category_shape_stats"].get(c) for c in cats
                                    if digest["category_shape_stats"].get(c)},
        }

    out = json.dumps(bundle, indent=1, ensure_ascii=False, default=str)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"bundle -> {args.out} ({len(out)/1024:.1f} KB)", file=sys.stderr)
    else:
        print(out)


# ----------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cache", default=".gmt_cache", help="directory for cached API responses")
    p.add_argument("--pause", type=float, default=0.2, help="seconds between API calls")
    p.add_argument("--refresh", action="store_true", help="ignore cache")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("digest", help="build the Energy-ID digest")
    d.add_argument("--out", default="energy_id_digest.json")
    d.set_defaults(func=cmd_digest)

    rr = sub.add_parser("run", help="build the bundle for one run")
    rr.add_argument("run_id")
    rr.add_argument("--digest", help="energy_id_digest.json (optional)")
    rr.add_argument("--out", help="output file (default: stdout)")
    rr.add_argument("--max-alternatives", type=int, default=10)
    rr.set_defaults(func=cmd_run)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
