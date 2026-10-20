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

IDLE_CPU_PCT = 5.0        # CALIBRATE: fallback idle criterion when no baseline power exists
IDLE_POWER_RATIO = 1.05   # CALIBRATE: phase power <= baseline power * this -> "mostly idle"
NOISE_PCT = 5.0           # CALIBRATE: deltas below this are treated as measurement noise
BASELINE_DRIFT = 0.01     # CALIBRATE: assumed baseline drift (1 %) -> uncertainty of attributable energy


def attr_band(energy_j, attributable_j):
    """uncertainty of attributable energy = drift * baseline part of the energy"""
    if energy_j is None or attributable_j is None:
        return None
    return BASELINE_DRIFT * max(energy_j - attributable_j, 0.0)


def excess_w(attributable_j, duration_s):
    if attributable_j is None or not duration_s:
        return None
    return attributable_j / duration_s


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
            "carbon_intensity_g_per_kwh": r(ci, 1) if ci is not None else
                (r(carbon / (e / 3.6e6), 1) if carbon and e else None),
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
            band = attr_band(ph["energy_j"], ph["attributable_energy_j"])
            ph["attributable_uncertainty_j"] = r(band)
            ph["attributable_within_noise"] = ph["attributable_energy_j"] <= band
            ph["excess_power_w"] = r(excess_w(ph["attributable_energy_j"], ph["duration_s"]), 3)
        else:
            ph["attributable_energy_j"] = None
            ph["attributable_uncertainty_j"] = None
            ph["attributable_within_noise"] = None
            ph["excess_power_w"] = None
        if name in top:
            ph["share_of_total_pct"] = pct(ph["energy_j"], total_e)
            total_attr += ph["attributable_energy_j"] or 0
    rt_e = (phases.get("[RUNTIME]") or {}).get("energy_j")
    for name, ph in phases.items():
        if ph["is_flow"]:
            ph["share_of_runtime_pct"] = pct(ph["energy_j"], rt_e)
        cpu = ph["cpu_util_system_pct"]
        if base_p and ph["power_w"] is not None:
            ph["power_vs_baseline"] = r(ph["power_w"] / base_p, 3)
            ph["mostly_idle"] = ph["power_w"] <= base_p * IDLE_POWER_RATIO
        else:
            ph["power_vs_baseline"] = None
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

# ----------------------------------------------------------------------------
# SBOM / container dependencies (collected by GMT via energy-dependency-inspector)
# ----------------------------------------------------------------------------

# curated, energy-relevant packages. pattern (regex on package name) -> (category, hint)
# Hints are starting points for the agent, not measured facts.
NOTABLE_PACKAGES = [
    (r"^(zlib-ng|zlib-ng-compat|libdeflate.*|isa-l|pigz)$", "compression", "fast compression drop-in already present"),
    (r"^(zstandard|lz4|brotli|python-snappy|snappy|zlib-ng|isal)$", "compression", "compression library used by the application - codec and level matter for CPU"),
    (r"^(orjson|ujson|simplejson|msgpack|rapidjson|python-rapidjson)$", "serialization", "fast JSON/serialization library in use"),
    (r"^(json|jsonlib)$", "serialization", "check if a faster JSON library (orjson) is possible"),
    (r"^(valgrind|gdb|strace|ltrace|linux-tools.*|perf|python3-dbg|.*-dbg|.*-dbgsym)$", "debug_tooling", "debug/profiling tooling in the runtime image"),
    (r"^(build-essential|gcc(-\d+)?|g\+\+(-\d+)?|make|cmake|clang(-\d+)?)$", "build_toolchain", "build toolchain shipped in runtime image - multi-stage build could drop it"),
    (r"^(man-db|manpages.*|info|doc-base)$", "image_bloat", "documentation packages in image"),
    (r"^(openjdk-\d+-.*|default-jre.*|temurin.*)$", "runtime", "JVM present - heap/GC settings are an energy lever"),
    (r"^(python3(\.\d+)?|nodejs|php\d*(\.\d+)?|ruby\d*(\.\d+)?)$", "runtime", "interpreter runtime"),
    (r"^(nginx|apache2|httpd|caddy|redis(-server)?|valkey|memcached|postgresql(-\d+)?|mariadb-server|mysql-server|mssql-server|mongodb.*)$", "server", "server software - check Energy ID for measured alternatives"),
]

DEP_MANAGER_KEYS = ("dpkg", "apk", "pip", "npm", "maven", "composer", "pecl")


def iter_dependency_managers(container_deps):
    """yield (manager, scope, {pkg: {version,...}}) for one container's dependency dict"""
    for key, val in (container_deps or {}).items():
        if isinstance(val, dict) and isinstance(val.get("dependencies"), dict):
            yield key, val.get("scope"), val["dependencies"]


def container_metadata(container_deps):
    meta = {}
    for key, val in (container_deps or {}).items():
        if isinstance(val, dict) and "dependencies" not in val:
            for k in ("image", "hash", "os", "kernel_version", "os_name"):
                if val.get(k) is not None and k not in meta:
                    meta[k] = str(val[k])[:120]
    return meta


def dependency_set(run):
    """{(container, manager, package): version}"""
    out = {}
    for cname, cdeps in (run.get("container_dependencies") or {}).items():
        for mgr, _scope, deps in iter_dependency_managers(cdeps):
            for pkg, info in deps.items():
                out[(cname, mgr, pkg)] = (info or {}).get("version") if isinstance(info, dict) else str(info)
    return out


def name_tokens(*texts):
    stop = {"com", "www", "github", "docker", "library", "latest", "image", "container", "benchmark",
            "bench", "run", "the", "and", "usage", "scenario", "yml", "main", "mcr", "microsoft", "io"}
    toks = set()
    for t in texts:
        for w in re.split(r"[^a-z0-9]+", (t or "").lower()):
            if len(w) >= 3 and w not in stop and not w.isdigit():
                toks.add(w)
    return toks


def dependency_summary(run, software_names=()):
    deps = run.get("container_dependencies") or {}
    if not deps:
        return None
    tokens = name_tokens(run.get("name"), run.get("filename"), *software_names)
    containers = {}
    for cname, cdeps in deps.items():
        managers, notable, main = {}, defaultdict(list), []
        dev_count = 0
        for mgr, scope, pkgs in iter_dependency_managers(cdeps):
            managers[mgr] = {"scope": scope, "count": len(pkgs)}
            for pkg, info in pkgs.items():
                ver = (info or {}).get("version") if isinstance(info, dict) else str(info)
                low = pkg.lower()
                if low.endswith("-dev"):
                    dev_count += 1
                for rx, cat, hint in NOTABLE_PACKAGES:
                    if cat == "compression" and mgr in ("dpkg", "apk") and not re.match(r"^(zlib-ng.*|libdeflate.*|isa-l|pigz)$", low):
                        continue
                    if re.match(rx, low):
                        notable[cat].append({"package": pkg, "manager": mgr, "version": ver, "hint": hint})
                        break
                if any(tok in low for tok in tokens) and len(main) < 8:
                    main.append({"package": pkg, "manager": mgr, "version": ver})
        meta = container_metadata(cdeps)
        image = meta.get("image") or ""
        tag = image.rsplit(":", 1)[1] if ":" in image.split("/")[-1] else None
        containers[cname] = {
            **meta,
            "image_tag": tag,
            "coverage_note": (None if managers else
                              "no packages detected - package manager of this image (e.g. rpm/dnf) is not covered by the inspector"),
            "packages_per_manager": managers,
            "packages_total": sum(m["count"] for m in managers.values()),
            "dev_packages": dev_count,
            "main_software_candidates": main,
            "notable_packages": {k: v[:8] for k, v in notable.items()},
        }
    return containers


def dependency_diff(run_a, run_b, limit=15):
    a, b = dependency_set(run_a), dependency_set(run_b)
    if not a or not b:
        return None
    changed = [{"container": k[0], "manager": k[1], "package": k[2], "this_run": a[k], "other": b[k]}
               for k in a.keys() & b.keys() if a[k] != b[k]]
    added = [k for k in b.keys() - a.keys()]
    removed = [k for k in a.keys() - b.keys()]
    return {
        "changed_versions": len(changed),
        "only_in_other": len(added),
        "only_in_this_run": len(removed),
        "examples": sorted(changed, key=lambda x: x["package"])[:limit],
        "identical": not changed and not added and not removed,
    }


def host_packages_hash(run):
    import hashlib
    v = (run.get("machine_specs") or {}).get("Installed System Packages")
    return hashlib.sha1(str(v).encode()).hexdigest()[:12] if v else None


# ----------------------------------------------------------------------------
# repetitions and per-phase comparison
# ----------------------------------------------------------------------------

def stats_of(values):
    v = [x for x in values if x is not None]
    if not v:
        return None
    mean = statistics.fmean(v)
    sd = statistics.stdev(v) if len(v) > 1 else None
    return {"n": len(v), "mean": r(mean), "stddev": r(sd) if sd is not None else None,
            "cv_pct": r(100 * sd / mean, 1) if sd is not None and mean else None,
            "min": r(min(v)), "max": r(max(v))}


def repetition_analysis(api, run, summary, rep_rows, max_reps):
    """fetch repetitions of the same scenario and compute spread per phase"""
    same = [row for row in rep_rows
            if row[0] != run["id"] and row[3] == run.get("branch")
            and json.dumps(row[7], sort_keys=True) == json.dumps(run.get("usage_scenario_variables"), sort_keys=True)]
    same = same[:max_reps]
    reps = []
    for row in same:
        rrun = api.get(f"/v2/run/{row[0]}") or {}
        rstats = api.get(f"/v1/phase_stats/single/{row[0]}") or {}
        try:
            rsum = summarize_run(rrun, rstats)
        except Exception:
            continue
        if rsum["energy_scope"] != summary["energy_scope"]:
            continue
        reps.append((row, rrun, rsum))

    phase_names = [p for p in summary["phases"] if p != "[BASELINE]"]
    phases = {}
    for p in phase_names:
        vals = [summary["phases"][p]["energy_j"]] + [(rs["phases"].get(p) or {}).get("energy_j") for _, _, rs in reps]
        durs = [summary["phases"][p]["duration_s"]] + [(rs["phases"].get(p) or {}).get("duration_s") for _, _, rs in reps]
        st = stats_of(vals)
        if st:
            st["duration"] = stats_of(durs)
            this = summary["phases"][p]["energy_j"]
            st["this_run_vs_mean_pct"] = pct(this - st["mean"], st["mean"]) if this is not None and st["mean"] else None
            phases[p] = st

    rt = phases.get("[RUNTIME]") or {}
    cv = rt.get("cv_pct")
    effective_noise = max(r(2 * cv, 1), 1.0) if cv is not None and rt.get("n", 0) >= 3 else NOISE_PCT

    host_hash = host_packages_hash(run)
    rep_list = []
    for row, rrun, rsum in reps:
        rt_e = (rsum["phases"].get("[RUNTIME]") or {}).get("energy_j")
        own_rt = (summary["phases"].get("[RUNTIME]") or {}).get("energy_j")
        diff = dependency_diff(run, rrun)
        rep_list.append({
            "run_id": row[0], "created_at": row[4], "commit_hash": row[9],
            "runtime_energy_j": rt_e,
            "runtime_delta_vs_this_run_pct": pct(rt_e - own_rt, own_rt) if rt_e is not None and own_rt else None,
            "host_packages_changed": (host_packages_hash(rrun) != host_hash) if host_hash else None,
            "dependency_diff": None if not diff else (
                {"identical": True} if diff["identical"] else diff),
        })

    return {
        "n_total_including_this_run": 1 + len(reps),
        "n_available_same_scenario": len(rep_rows),
        "filter": "same uri, filename, machine, branch and usage_scenario_variables; not failed",
        "phases": phases,
        "measured_noise_pct": effective_noise if cv is not None and rt.get("n", 0) >= 3 else None,
        "effective_noise_pct": effective_noise,
        "runs": rep_list,
    }


def phase_comparison(summary_a, summary_b):
    """compare phases with identical names (standard + flow phases)"""
    rows = []
    for name, pa in summary_a["phases"].items():
        pb = summary_b["phases"].get(name)
        if not pb or name == "[BASELINE]":
            continue
        rows.append({
            "phase": name,
            "this_run_duration_s": pa["duration_s"], "other_duration_s": pb["duration_s"],
            "this_run_energy_j": pa["energy_j"], "other_energy_j": pb["energy_j"],
            "energy_delta_pct": pct((pb["energy_j"] or 0) - pa["energy_j"], pa["energy_j"]) if pa["energy_j"] else None,
            "this_run_excess_power_w": pa.get("excess_power_w"), "other_excess_power_w": pb.get("excess_power_w"),
            "this_run_cpu_pct": pa.get("cpu_util_system_pct"), "other_cpu_pct": pb.get("cpu_util_system_pct"),
        })
    return rows


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
    rid = resolve_run_id(args.run_id, args.digest)
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
    rep_info = repetition_analysis(api, run, summary, reps, args.max_reps) if args.max_reps > 0 else None
    noise = rep_info["effective_noise_pct"] if rep_info else NOISE_PCT

    bundle = {
        "bundle_version": "0.6",
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
            "host_packages_hash": host_packages_hash(run),
        },
        "repetitions": rep_info,
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

        # a task is ambiguous on a machine if one software appears with several scenarios
        sw_count = defaultdict(lambda: defaultdict(set))
        for t in digest["tasks"]:
            if t.get("energy_j") is not None:
                sw_count[(t["task"], t["machine_id"])][t["software"]].add((t["uri"], t["filename"]))
        ambiguous = {k for k, sws in sw_count.items() if any(len(v) > 1 for v in sws.values())}

        alternatives = []
        for name in task_names:
            # reference value of THIS run for the task (same phase), measured in this run
            own_t = next((t for t in own if t["task"] == name), None)
            own_phase = (summary["phases"].get(own_t["phase"]) or {}) if own_t else {}
            for t in digest["tasks"]:
                if (t["task"] != name or t.get("energy_j") is None
                        or (t["uri"] == run.get("uri") and t["filename"] == run.get("filename"))):
                    continue
                same_machine = t["machine_id"] == run.get("machine_id")
                same_scope = t.get("energy_scope") == summary["energy_scope"]
                delta = delta_attr = None
                if same_machine and same_scope and own_phase.get("energy_j"):
                    delta = pct(t["energy_j"] - own_phase["energy_j"], own_phase["energy_j"])
                    a_own, a_alt = own_phase.get("attributable_energy_j"), t.get("attributable_energy_j")
                    b_own = attr_band(own_phase.get("energy_j"), a_own)
                    b_alt = attr_band(t.get("energy_j"), a_alt)
                    # % delta only if both attributable values are clearly above their noise band
                    if a_own and a_alt is not None and b_own is not None and b_alt is not None \
                            and a_own > b_own and a_alt > b_alt:
                        delta_attr = pct(a_alt - a_own, a_own)
                alternatives.append({
                    "task": name, "phase": t["phase"], "software": t["software"],
                    "machine_id": t["machine_id"], "machine": t["machine"],
                    "energy_j": t["energy_j"], "duration_s": t["duration_s"], "power_w": t["power_w"],
                    "run_id": t["run_id"],
                    "attributable_energy_j": t.get("attributable_energy_j"),
                    "excess_power_w": r(excess_w(t.get("attributable_energy_j"), t.get("duration_s")), 3),
                    "this_run_excess_power_w": own_phase.get("excess_power_w"),
                    "this_run_energy_j": own_phase.get("energy_j"),
                    "this_run_attributable_energy_j": own_phase.get("attributable_energy_j"),
                    "delta_vs_this_run_pct": delta,
                    "delta_attributable_vs_this_run_pct": delta_attr,
                    "beyond_noise": (delta is not None and abs(delta) >= noise),
                    "ambiguous_task": (name, t["machine_id"]) in ambiguous,
                    "comparable": same_machine and same_scope and (name, t["machine_id"]) not in ambiguous,
                    "note": ("same task name used by several scenarios of one software on this machine - not comparable"
                             if (name, t["machine_id"]) in ambiguous else
                             None if (same_machine and same_scope)
                             else "different machine or energy scope - indicative only, use ratios not absolutes"),
                })
        alternatives.sort(key=lambda a: (not a["comparable"], a["delta_vs_this_run_pct"] if a["delta_vs_this_run_pct"] is not None else 1e9))

        # aggregate per alternative software over all tasks it shares with this run (comparable only)
        agg = defaultdict(lambda: {"tasks": 0, "energy_j": 0.0, "this_run_energy_j": 0.0,
                                   "attributable_energy_j": 0.0, "this_run_attributable_energy_j": 0.0,
                                   "duration_s": 0.0, "this_run_duration_s": 0.0,
                                   "attr_complete": True, "run_ids": set()})
        for a in alternatives:
            if not a["comparable"] or a["this_run_energy_j"] is None:
                continue
            g = agg[a["software"]]
            g["tasks"] += 1
            g["energy_j"] += a["energy_j"]
            g["duration_s"] += a["duration_s"] or 0
            g["this_run_duration_s"] += (summary["phases"].get(a["phase"]) or {}).get("duration_s") or 0
            g["this_run_energy_j"] += a["this_run_energy_j"]
            g["run_ids"].add(a["run_id"])
            if a["attributable_energy_j"] is None or a["this_run_attributable_energy_j"] is None:
                g["attr_complete"] = False
            else:
                g["attributable_energy_j"] += a["attributable_energy_j"]
                g["this_run_attributable_energy_j"] += a["this_run_attributable_energy_j"]
        by_software = []
        for sw, g in agg.items():
            d = pct(g["energy_j"] - g["this_run_energy_j"], g["this_run_energy_j"])
            band_alt = attr_band(g["energy_j"], g["attributable_energy_j"]) if g["attr_complete"] else None
            band_own = attr_band(g["this_run_energy_j"], g["this_run_attributable_energy_j"]) if g["attr_complete"] else None
            da = None
            if g["attr_complete"] and g["attributable_energy_j"] > band_alt and g["this_run_attributable_energy_j"] > band_own:
                da = pct(g["attributable_energy_j"] - g["this_run_attributable_energy_j"], g["this_run_attributable_energy_j"])
            ex_alt = excess_w(g["attributable_energy_j"], g["duration_s"]) if g["attr_complete"] else None
            ex_own = excess_w(g["this_run_attributable_energy_j"], g["this_run_duration_s"]) if g["attr_complete"] else None
            by_software.append({
                "software": sw, "shared_tasks": g["tasks"],
                "energy_j": r(g["energy_j"]), "this_run_energy_j": r(g["this_run_energy_j"]),
                "delta_pct": d,
                "attributable_energy_j": r(g["attributable_energy_j"]) if g["attr_complete"] else None,
                "this_run_attributable_energy_j": r(g["this_run_attributable_energy_j"]) if g["attr_complete"] else None,
                "attributable_uncertainty_j": r(band_alt),
                "this_run_attributable_uncertainty_j": r(band_own),
                "delta_attributable_pct": da,
                "excess_power_w": r(ex_alt, 3),
                "this_run_excess_power_w": r(ex_own, 3),
                "excess_power_diff_w": r(ex_alt - ex_own, 3) if ex_alt is not None and ex_own is not None else None,
                "beyond_noise": d is not None and abs(d) >= noise,
                "run_ids": sorted(g["run_ids"]),
            })
        by_software.sort(key=lambda x: x["delta_pct"] if x["delta_pct"] is not None else 1e9)

        # detail for the best comparable alternatives: phase-by-phase + their SBOM summary
        for entry in [b for b in by_software][: args.max_alt_detail]:
            arid = entry["run_ids"][0]
            arun = api.get(f"/v2/run/{arid}") or {}
            astats = api.get(f"/v1/phase_stats/single/{arid}") or {}
            try:
                asum = summarize_run(arun, astats)
                entry["phase_comparison"] = phase_comparison(summary, asum)
                entry["other_baseline_power_w"] = asum["baseline_power_w"]
            except Exception as exc:
                entry["phase_comparison_error"] = str(exc)
            entry["dependencies"] = dependency_summary(arun, [entry["software"]])

        own_software = sorted({t["software"] for t in own})
        bundle["dependencies"] = dependency_summary(run, own_software)

        bundle["energy_id"] = {
            "digest_generated_at": digest.get("generated_at"),
            "matched_tasks": task_names,
            "noise_threshold_pct": noise,
            "noise_threshold_source": "measured from repetitions (2 x CV of [RUNTIME])" if rep_info and rep_info["measured_noise_pct"] is not None else "default (CALIBRATE)",
            "baseline_drift_assumed": BASELINE_DRIFT,
            "alternatives_by_software": by_software,
            "alternatives": alternatives[: args.max_alternatives],
            "category_peer_stats": {c: digest["category_shape_stats"].get(c) for c in cats
                                    if digest["category_shape_stats"].get(c)},
        }

    if "dependencies" not in bundle:
        bundle["dependencies"] = dependency_summary(run)

    if args.cross:
        bundle["cross_benchmark"], bundle["configuration_tiers"] = cross_slice(run, summary, args.cross)

    out = json.dumps(bundle, indent=1, ensure_ascii=False, default=str)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"bundle -> {args.out} ({len(out)/1024:.1f} KB)", file=sys.stderr)
    else:
        print(out)


def cross_slice(run, summary, cross_path):
    """attach the cross-benchmark factors and the configuration tiers for this run's DBMS"""
    cross = json.loads(Path(cross_path).read_text(encoding="utf-8"))
    if cross.get("uri") != run.get("uri") or cross.get("machine_id") != run.get("machine_id"):
        return ({"note": "cross file is for another repo/machine - not used"}, None)
    fn = (run.get("filename") or "").lower()
    bench = next((b for b in cross.get("benchmarks", []) if b in fn), None)
    dbms = Path(fn).stem
    factors = (cross.get("relative_factors") or {}).get(dbms)
    cb = {
        "dbms": dbms, "benchmark_of_this_run": bench,
        "factors": ({cls: {k: v for k, v in f.items() if k != "per_variant"} for cls, f in factors.items()}
                    if factors else None),
        "rank_consistency_mean_spearman": {cls: (v or {}).get("mean_spearman")
                                           for cls, v in (cross.get("rank_consistency_spearman") or {}).items()},
        "workload_type": {k: v["type"] for k, v in (cross.get("workload_type") or {}).items()},
        "note": cross.get("note"),
    }
    ct = cross.get("configuration_tiers")
    if not ct:
        return cb, None
    desc = ct.get("descriptions") or {}
    branch = run.get("branch")
    has_configure = any(classify_flow(p) == "configure" for p in summary["phases"])
    if branch in desc:
        current = {"tier": branch, "source": "branch name"}
    elif not has_configure:
        current = {"tier": "t0-like", "source": "no 'Configure DBMS' step - server runs with shipped defaults"}
    else:
        current = {"tier": "unknown", "source": f"branch '{branch}' has a configure step but is not a known tier"}
    by_bd = ct.get("by_benchmark_dbms") or {}
    rows = by_bd.get(f"{bench}/{dbms}")
    # energy per unit of work of every DBMS in this benchmark (T3 = energy-optimal config)
    own_ju = ((rows or {}).get("t3_cell") or {}).get("t3_j_per_unit_confirmed")
    ju_all = {}
    for key, e in by_bd.items():
        b, d = key.split("/")
        ju = (e.get("t3_cell") or {}).get("t3_j_per_unit_confirmed")
        if b == bench and ju:
            ju_all[d] = {"t3_j_per_unit": ju, "vs_this_dbms": r(ju / own_ju, 2) if own_ju else None}
    return cb, {
        "descriptions": desc,
        "this_run": current,
        "benchmark_dbms": f"{bench}/{dbms}",
        "measured_tiers": rows,
        "j_per_unit_t3_all_dbms": dict(sorted(ju_all.items(), key=lambda kv: kv[1]["t3_j_per_unit"])),
        "note": ct.get("note"),
    }


def cmd_candidates(args):
    digest = json.loads(Path(args.digest).read_text(encoding="utf-8"))
    cats = {c.strip().lower() for c in args.categories.split(",") if c.strip()}
    groups = defaultdict(list)
    for t in digest["tasks"]:
        if t.get("energy_j") is None or not t.get("duration_s") or t.get("attributable_energy_j") is None:
            continue
        if cats and not any(c.lower() in cats for c in t["categories"]):
            continue
        if args.machine and args.machine.lower() not in (t["machine"] or "").lower():
            continue
        groups[(t["task"], t["machine"])].append(t)
    rows = [(k, v) for k, v in groups.items() if len(v) >= args.min_software]
    rows.sort(key=lambda kv: -max(x["attributable_energy_j"] / x["duration_s"] for x in kv[1]))
    for (task, machine), v in rows[: args.limit]:
        print(f"{len(v)} x | {task} | {machine}")
        for x in sorted(v, key=lambda x: x["energy_j"]):
            print(f"    {x['software']:<32} {x['energy_j']:>10.0f} J  +{x['attributable_energy_j']/x['duration_s']:6.1f} W   {x['run_id']}")
    if not rows:
        print("no matching tasks")


# ----------------------------------------------------------------------------
# stage 3: cross-benchmark comparison (same repo + machine, several benchmarks x DBMS)
# ----------------------------------------------------------------------------

def classify_flow(name):
    n = name.lower()
    # order matters: "workload" contains "load"
    if re.search(r"\b(warm ?up|warmup)\b", n):
        return "warmup"
    if re.search(r"\b(configure|config|tune|tuning)\b", n):
        return "configure"
    if re.search(r"\b(drop|cleanup|clean up|teardown|remove)\b", n):
        return "teardown"
    if re.search(r"\b(workload|execute|benchmark|queries|query|transactions?)\b", n) or n.startswith("run "):
        return "workload"
    if re.search(r"\b(load|loading|populate|import|insert data|fill|build)\b", n):
        return "load"
    if re.search(r"\b(create|setup|prepare|schema)\b", n):
        return "setup"
    return "other"


def spearman(xs, ys):
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        rk = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for k in range(i, j + 1):
                rk[order[k]] = (i + j) / 2 + 1
            i = j + 1
        return rk
    if len(xs) < 3:
        return None
    rx, ry = ranks(xs), ranks(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    vx = sum((a - mx) ** 2 for a in rx) ** 0.5
    vy = sum((b - my) ** 2 for b in ry) ** 0.5
    return r(cov / (vx * vy), 2) if vx and vy else None


def cmd_cross(args):
    api = Api(Path(args.cache), args.pause, args.refresh)
    benches = [b.strip().lower() for b in args.benchmarks.split(",") if b.strip()]
    base = {"uri": args.uri, "uri_mode": "exact", "machine_id": args.machine_id, "failed": False, "limit": 50}

    rows = {}
    for b in benches:
        for row in api.get("/v2/runs", {**base, "filename": b}) or []:
            rows[row[0]] = row
    if args.branch:
        rows = {k: v for k, v in rows.items() if v[3] == args.branch}

    # group by scenario: benchmark (matched substring), dbms (file stem), branch, variables
    groups = defaultdict(list)
    for row in rows.values():
        fn = (row[6] or "").lower()
        bench = next((b for b in benches if b in fn), None)
        if not bench:
            continue
        dbms = Path(fn).stem
        variables = json.dumps(row[7], sort_keys=True) if row[7] else "{}"
        groups[(bench, dbms, row[6], row[3], variables)].append(row)

    scenarios, flow_names = [], defaultdict(set)
    for (bench, dbms, fn, branch, variables), rws in sorted(groups.items()):
        rws.sort(key=lambda x: str(x[4]), reverse=True)  # newest first
        per_class = defaultdict(lambda: {"energy_j": [], "duration_s": [], "excess_power_w": []})
        runtime_e, used = [], []
        print(f"  {bench:<10} {dbms:<8} {branch:<20} ({min(len(rws), args.reps)} runs)", file=sys.stderr, flush=True)
        for row in rws[: args.reps]:
            run = api.get(f"/v2/run/{row[0]}") or {}
            st = api.get(f"/v1/phase_stats/single/{row[0]}") or {}
            try:
                sm = summarize_run(run, st)
            except Exception:
                continue
            used.append(row[0])
            runtime_e.append((sm["phases"].get("[RUNTIME]") or {}).get("energy_j"))
            sums = defaultdict(lambda: [0.0, 0.0, 0.0])
            for pname, ph in sm["phases"].items():
                if not ph["is_flow"]:
                    continue
                cls = classify_flow(pname)
                flow_names[bench].add(f"{pname} -> {cls}")
                sums[cls][0] += ph["energy_j"] or 0
                sums[cls][1] += ph["duration_s"] or 0
                sums[cls][2] += ph["attributable_energy_j"] or 0
            for cls, (e, d, a) in sums.items():
                per_class[cls]["energy_j"].append(e)
                per_class[cls]["duration_s"].append(d)
                per_class[cls]["excess_power_w"].append(a / d if d else None)
        if not used:
            continue
        scenarios.append({
            "benchmark": bench, "dbms": dbms, "filename": fn, "branch": branch,
            "usage_scenario_variables": json.loads(variables), "runs_used": used,
            "runs_available": len(rws),
            "runtime_energy": stats_of(runtime_e),
            "phases": {cls: {k: stats_of(v) for k, v in d.items()} for cls, d in per_class.items()},
        })

    branches = {s_["branch"] for s_ in scenarios if re.fullmatch(r"t\d", s_["branch"] or "")}
    tiers, cells = load_tiers(args.uri, branches, args.cache) if branches else ({}, {})
    result = analyse_cross(scenarios, benches, dict(flow_names), args.uri, args.machine_id, tiers, cells)
    result["runs_found"] = len(rows)
    write_cross(result, args.out)


# ----------------------------------------------------------------------------
# configuration tiers (DBMS-bench branches t0..t3, described in TIERS.md per branch)
# ----------------------------------------------------------------------------

def raw_github_url(repo_uri, branch, path):
    m = re.match(r"https?://github\.com/([^/]+)/([^/.]+)", repo_uri or "")
    return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{branch}/{path}" if m else None


def fetch_text(url, cache_dir):
    cache = Path(cache_dir) / ("raw_" + re.sub(r"[^A-Za-z0-9_.-]+", "_", url)[-180:])
    if cache.exists():
        return cache.read_text(encoding="utf-8")
    try:
        resp = requests.get(url, timeout=60)
        txt = resp.text if resp.status_code == 200 else ""
    except requests.RequestException:
        txt = ""
    cache.write_text(txt, encoding="utf-8")
    return txt


def parse_tier_description(md, branch):
    """short description of a tier from its TIERS.md"""
    tier = branch.upper()
    m = re.search(rf"\*\*({tier}:[^*]+)\*\*", md)
    if m:
        return m.group(1).strip()
    m = re.search(rf"^#\s*({tier}:[^\n]+)", md, re.M)
    if m:
        return re.sub(r"\s*\(branch.*\)$", "", m.group(1)).strip()
    first = md.strip().splitlines()[0].lstrip("# ").strip() if md.strip() else ""
    return first or None


def parse_t3_cells(md):
    """TIERS.md of t3: | engine/workload | trial | a to b | confirmed | differs | -> dict"""
    cells = {}
    for line in md.splitlines():
        parts = [p.strip() for p in line.strip().strip("|").split("|")]
        if len(parts) < 5 or "/" not in parts[0] or parts[0].lower() == "cell" or set(parts[0]) <= {"-"}:
            continue
        engine, workload = parts[0].split("/", 1)
        search = re.match(r"([\d.eE-]+)\s*to\s*([\d.eE-]+)", parts[2])
        try:
            confirmed = float(parts[3])
        except ValueError:
            confirmed = None
        knobs = []
        if not parts[4].lower().startswith("nothing"):
            for k in parts[4].split(";"):
                km = re.match(r"\s*(.+?):\s*(.+?)\s+to\s+(.+?)\s*$", k)
                if km:
                    knobs.append({"parameter": km.group(1), "t2": km.group(2), "t3": km.group(3)})
        cells[(engine.strip().lower(), workload.strip().lower())] = {
            "t3_j_per_unit_confirmed": confirmed,
            "search_host_j_per_unit_t2": float(search.group(1)) if search else None,
            "search_host_j_per_unit_t3": float(search.group(2)) if search else None,
            "t3_changes_vs_t2": knobs,
            "note": parts[4] if not knobs else None,
        }
    return cells


def load_tiers(repo_uri, branches, cache_dir):
    tiers, cells = {}, {}
    for b in sorted(branches):
        url = raw_github_url(repo_uri, b, "TIERS.md")
        md = fetch_text(url, cache_dir) if url else ""
        if not md:
            continue
        tiers[b] = parse_tier_description(md, b)
        if b.lower() == "t3":
            cells = parse_t3_cells(md)
    return tiers, cells


def tier_table(scenarios, tiers, cells):
    """per (benchmark, dbms): energy/duration per phase class and tier + T3 knobs/J-unit"""
    out = {}
    for s_ in scenarios:
        if s_["branch"] not in tiers:
            continue
        key = f"{s_['benchmark']}/{s_['dbms']}"
        entry = out.setdefault(key, {"tiers": {}})
        row = {"runtime_energy_j": (s_["runtime_energy"] or {}).get("mean"), "n_runs": len(s_["runs_used"])}
        for cls in ("load", "workload"):
            p = s_["phases"].get(cls) or {}
            row[f"{cls}_energy_j"] = (p.get("energy_j") or {}).get("mean")
            row[f"{cls}_duration_s"] = (p.get("duration_s") or {}).get("mean")
            row[f"{cls}_excess_power_w"] = (p.get("excess_power_w") or {}).get("mean")
        entry["tiers"][s_["branch"]] = row
    for key, entry in out.items():
        bench, dbms = key.split("/")
        t = entry["tiers"]
        base = t.get("t0") or {}
        for b, row in t.items():
            for cls in ("runtime", "load", "workload"):
                k = "runtime_energy_j" if cls == "runtime" else f"{cls}_energy_j"
                row[f"{cls}_delta_vs_t0_pct"] = (pct(row[k] - base[k], base[k])
                                                 if row.get(k) is not None and base.get(k) else None)
        cell = cells.get((dbms, bench))
        if cell:
            entry["t3_cell"] = cell
    return out


def analyse_cross(scenarios, benches, flow_names, uri, machine_id, tiers=None, cells=None):
    """factors per benchmark variant (benchmark@branch[+vars]) and DBMS"""
    multi_branch = defaultdict(set)
    for s_ in scenarios:
        multi_branch[s_["benchmark"]].add((s_["branch"], json.dumps(s_["usage_scenario_variables"], sort_keys=True)))

    def variant(s_):
        if len(multi_branch[s_["benchmark"]]) == 1:
            return s_["benchmark"]
        v = s_["usage_scenario_variables"]
        return f"{s_['benchmark']}@{s_['branch']}" + (f"+{json.dumps(v, sort_keys=True)}" if v else "")

    seen = defaultdict(list)
    for s_ in scenarios:
        s_["variant"] = variant(s_)
        seen[(s_["variant"], s_["dbms"])].append(s_["filename"])
    ambiguous = {f"{k[0]}/{k[1]}": v for k, v in seen.items() if len(v) > 1}

    def mean_of(s_, cls, key="energy_j"):
        if cls == "runtime":
            return (s_["runtime_energy"] or {}).get("mean")
        return ((s_["phases"].get(cls) or {}).get(key) or {}).get("mean")

    # workload type per variant: time-boxed if all DBMS run (almost) equally long
    variants = sorted({s_["variant"] for s_ in scenarios})
    workload_type = {}
    for v in variants:
        durs = [mean_of(s_, "workload", "duration_s") for s_ in scenarios if s_["variant"] == v]
        durs = [d for d in durs if d]
        if len(durs) >= 2:
            spread = (max(durs) - min(durs)) / statistics.median(durs)
            workload_type[v] = {"type": "time_boxed" if spread < 0.25 else "fixed_work",
                                "duration_min_s": r(min(durs)), "duration_max_s": r(max(durs))}

    classes = ("runtime", "load", "workload")
    factors = defaultdict(lambda: defaultdict(dict))
    rank_consistency = {}
    for cls in classes:
        per_var = defaultdict(dict)
        for s_ in scenarios:
            if f"{s_['variant']}/{s_['dbms']}" in ambiguous:
                continue
            val = mean_of(s_, cls)
            if val:
                per_var[s_["variant"]][s_["dbms"]] = val
        for v, vals in per_var.items():
            if len(vals) < 2:
                continue
            med = statistics.median(vals.values())
            for dbms, val in vals.items():
                factors[dbms][cls][v] = r(val / med, 2) if med else None
        vl = sorted(per_var)
        pairs = {}
        for i in range(len(vl)):
            for j in range(i + 1, len(vl)):
                common = sorted(set(per_var[vl[i]]) & set(per_var[vl[j]]))
                rho = spearman([per_var[vl[i]][d] for d in common], [per_var[vl[j]][d] for d in common])
                if rho is not None:
                    pairs[f"{vl[i]} vs {vl[j]}"] = rho
        rank_consistency[cls] = {
            "pairs": pairs,
            "mean_spearman": r(statistics.fmean(pairs.values()), 2) if pairs else None,
        }

    summary = {}
    for dbms, by_cls in factors.items():
        summary[dbms] = {}
        for cls, by_v in by_cls.items():
            vals = [x for x in by_v.values() if x]
            per_bench = defaultdict(list)
            for v, x in by_v.items():
                if x:
                    per_bench[v.split("@")[0]].append(x)
            summary[dbms][cls] = {
                "per_variant": by_v,
                "per_benchmark_geomean": {b: r(statistics.geometric_mean(x), 2) for b, x in per_bench.items()},
                "geomean": r(statistics.geometric_mean(vals), 2) if vals else None,
                "above_median_in": f"{sum(1 for x in vals if x > 1.05)}/{len(vals)}",
                "below_median_in": f"{sum(1 for x in vals if x < 0.95)}/{len(vals)}",
            }

    return {
        "uri": uri, "machine_id": machine_id, "benchmarks": benches,
        "note": ("factor = DBMS mean energy / median of all DBMS in that variant (1.0 = typical, >1 = more energy). "
                 "Variants = benchmark x branch (x variables); their meaning (e.g. tuning level) must be looked up. "
                 "Workload factors of time_boxed variants compare energy per time, not per work done."),
        "flow_phase_classification": {b: sorted(v) for b, v in flow_names.items()},
        "workload_type": workload_type,
        "ambiguous_scenarios": ambiguous,
        "relative_factors": summary,
        "rank_consistency_spearman": rank_consistency,
        "configuration_tiers": ({
            "descriptions": tiers,
            "note": ("Branches are configuration tiers: same schema, scale, clients and driver; only server "
                     "parameters differ. For time_boxed workloads energy per time rises when a tuned config "
                     "does more work - use t3_j_per_unit_confirmed (energy per unit of work) to judge efficiency."),
            "by_benchmark_dbms": tier_table(scenarios, tiers, cells or {}),
        } if tiers else None),
        "scenarios": scenarios,
    }


def write_cross(result, out):
    Path(out).write_text(json.dumps(result, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    summary = result["relative_factors"]
    print(f"{len(result['scenarios'])} scenarios")
    if result["ambiguous_scenarios"]:
        print("AMBIGUOUS (excluded):", ", ".join(result["ambiguous_scenarios"]))
    print("workload type:", ", ".join(f"{k}={v['type']}" for k, v in result["workload_type"].items()))
    benches = sorted({b for d in summary.values() for c in d.values() for b in c["per_benchmark_geomean"]})
    for cls in ("runtime", "load", "workload"):
        rc = result["rank_consistency_spearman"].get(cls, {})
        print(f"\n== {cls}: energy factor vs. median (geomean over variants) | mean spearman {rc.get('mean_spearman')} ==")
        print(f"{'dbms':<10}" + "".join(f"{b:>11}" for b in benches) + f"{'overall':>9}{'>1.05':>7}{'<0.95':>7}")
        for dbms in sorted(summary):
            f = summary[dbms].get(cls)
            if not f:
                continue
            cells = "".join(f"{(f['per_benchmark_geomean'].get(b) or '-')!s:>11}" for b in benches)
            print(f"{dbms:<10}{cells}{f['geomean']!s:>9}{f['above_median_in']:>7}{f['below_median_in']:>7}")
    ct = result.get("configuration_tiers")
    if ct:
        print("\n== configuration tiers ==")
        for b, d in ct["descriptions"].items():
            print(f"  {b}: {d}")
        print(f"\n{'benchmark/dbms':<20}" + "".join(f"{'wl '+t:>12}" for t in sorted(ct['descriptions'])) + f"{'wl t3 vs t0':>13}{'J/unit t3':>11}")
        for key, e in sorted(ct["by_benchmark_dbms"].items()):
            cells_ = "".join(f"{(e['tiers'].get(t) or {}).get('workload_energy_j') or '-'!s:>12}" for t in sorted(ct['descriptions']))
            t3 = e["tiers"].get("t3") or {}
            ju = (e.get("t3_cell") or {}).get("t3_j_per_unit_confirmed")
            print(f"{key:<20}{cells_}{str(t3.get('workload_delta_vs_t0_pct')):>13}{str(ju):>11}")
    print(f"\n-> {out}")


def cmd_cross_reanalyse(args):
    old = json.loads(Path(args.from_file).read_text(encoding="utf-8"))
    branches = {s_["branch"] for s_ in old["scenarios"] if re.fullmatch(r"t\d", s_["branch"] or "")}
    tiers, cells = load_tiers(old["uri"], branches, args.cache) if branches else ({}, {})
    res = analyse_cross(old["scenarios"], old["benchmarks"], old.get("flow_phase_classification", {}),
                        old["uri"], old["machine_id"], tiers, cells)
    write_cross(res, args.out)


def resolve_run_id(rid, digest_path):
    if len(rid) >= 36 or not digest_path:
        return rid
    tasks = json.loads(Path(digest_path).read_text(encoding="utf-8"))["tasks"]
    hits = sorted({t["run_id"] for t in tasks if t.get("run_id") and t["run_id"].startswith(rid)})
    if len(hits) != 1:
        sys.exit(f"run id prefix '{rid}' matches {len(hits)} runs in the digest")
    return hits[0]


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
    rr.add_argument("--max-reps", type=int, default=10, help="repetitions to analyse (0 = off)")
    rr.add_argument("--max-alt-detail", type=int, default=3, help="alternatives with phase-by-phase detail")
    rr.add_argument("--cross", help="cross_benchmark.json from the 'cross' command (optional)")
    rr.set_defaults(func=cmd_run)

    c = sub.add_parser("candidates", help="list Energy-ID tasks with several software on one machine")
    c.add_argument("--digest", default="energy_id_digest.json")
    c.add_argument("--categories", default="", help="comma separated, e.g. Database,SQL-Database")
    c.add_argument("--machine", default="", help="substring of the machine name")
    c.add_argument("--min-software", type=int, default=3)
    c.add_argument("--limit", type=int, default=10)
    c.set_defaults(func=cmd_candidates)

    x = sub.add_parser("cross", help="compare several benchmarks x DBMS of one repo on one machine")
    x.add_argument("--uri", default="https://github.com/green-coding-solutions/DBMS-bench")
    x.add_argument("--machine-id", type=int, default=13)
    x.add_argument("--benchmarks", default="wikipedia,tpch,tpcc", help="comma separated substrings of the scenario file path")
    x.add_argument("--branch", default="", help="optional: only this branch")
    x.add_argument("--reps", type=int, default=3, help="newest runs per scenario to average")
    x.add_argument("--out", default="cross_benchmark.json")
    x.add_argument("--from", dest="from_file", default="", help="re-analyse an existing cross JSON without API calls")
    x.set_defaults(func=lambda a: cmd_cross_reanalyse(a) if a.from_file else cmd_cross(a))

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
