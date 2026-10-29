#!/usr/bin/env python3
"""
gmt_dataset.py - turns GMT runs into a windowed training table for train_nn.py (--format gmt).

One row = one time window (default 1 s) of one run:
  identifiers : run_id, machine_id, machine, scenario, benchmark, dbms, branch, phase, t_s
  features    : cpu_util_pct, cpu_freq_mhz, temp, mem_used_bytes, disk_read_b, disk_write_b, net_b,
                container_cpu_util_pct   (missing on a machine -> empty)
  targets     : psu_energy_j (AC at the plug), rapl_cpu_j (package), rapl_mem_j (DRAM)
  context     : window_s, baseline_psu_w, baseline_rapl_cpu_w, baseline_rapl_mem_w

Sources of run ids (combine freely):
  --cross cross_benchmark.json   runs_used of every DBMS-bench scenario (t0..t3)
  --digest energy_id_digest.json run ids of all Energy-ID tasks
  --runs  id1,id2,...           explicit ids (e.g. your Windows runs on a local GMT, use --api)

Examples:
  python gmt_dataset.py --cross ..\\cross_benchmark.json --reps 1 --out data_cluster.csv.gz
  python gmt_dataset.py --api http://api.green-coding.internal:9142 --runs <id>,<id> --out data_laptop.csv.gz

Measurements are cached gzipped in --cache/measurements (several MB per run).
"""

import argparse
import csv
import gzip
import json
import math
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

PUBLIC_API = "https://api.green-coding.io"

# metric name -> (feature/target column, aggregation)
#   sum  : per-sample deltas (energy uJ, io bytes) summed over the window
#   mean : levels (utilization, memory, frequency, temperature) averaged over samples in the window
METRIC_MAP = [
    (r"^psu_energy_ac_.*_machine$", "psu_energy_j", "sum_uj"),
    (r"^cpu_energy_rapl_(msr|emi|scaphandre)_component$", "rapl_cpu_j", "sum_uj"),
    (r"^memory_energy_rapl_(msr|emi|scaphandre)_component$", "rapl_mem_j", "sum_uj"),
    (r"^cpu_utilization_(procfs|win32|mach|cgroup)_system$", "cpu_util_pct", "mean_ratio"),
    (r"^cpu_utilization_cgroup_container$", "container_cpu_util_pct", "mean_ratio_sum_details"),
    (r"^cpu_frequency_msr_core$", "cpu_freq_mhz", "mean_hz_over_details"),
    (r"^lmsensors_temperature_component$", "temp", "mean_over_details"),
    (r"^memory_used_(procfs|cgroup)_system$", "mem_used_bytes", "mean"),
    (r"^memory_used_cgroup_container$", "mem_used_bytes", "mean_sum_details"),
    (r"^disk_io_read_(procfs|cgroup)_system$", "disk_read_b", "sum"),
    (r"^disk_io_write_(procfs|cgroup)_system$", "disk_write_b", "sum"),
    (r"^disk_io_read_cgroup_container$", "disk_read_b", "sum"),
    (r"^disk_io_write_cgroup_container$", "disk_write_b", "sum"),
    (r"^network_io_(procfs|cgroup)_system$", "net_b", "sum"),
    (r"^network_io_cgroup_container$", "net_b", "sum"),
]
# priority when several metrics feed the same column (first wins)
SOURCE_RANK = ["_msr_", "_emi_", "_scaphandre_", "procfs_system", "win32_system", "cgroup_system", "cgroup_container"]

FEATURES = ["cpu_util_pct", "container_cpu_util_pct", "cpu_freq_mhz", "temp", "mem_used_bytes",
            "disk_read_b", "disk_write_b", "net_b"]
TARGETS = ["psu_energy_j", "rapl_cpu_j", "rapl_mem_j"]
ID_COLS = ["run_id", "machine_id", "machine", "scenario", "benchmark", "dbms", "branch", "phase", "t_s"]
CTX = ["window_s", "baseline_psu_w", "baseline_rapl_cpu_w", "baseline_rapl_mem_w"]

KEEP_PHASES_DEFAULT = ("[BASELINE]", "[IDLE]", "[RUNTIME]")


class Api:
    def __init__(self, base, cache, pause):
        self.base = base.rstrip("/")
        sub = "" if self.base == PUBLIC_API else re.sub(r"[^A-Za-z0-9]+", "_", self.base)
        self.cache = Path(cache) / sub if sub else Path(cache)
        (self.cache / "measurements").mkdir(parents=True, exist_ok=True)
        self.pause = pause
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "htw-caso-gmt-dataset/0.1"

    def _get(self, path):
        r = self.s.get(self.base + path, timeout=300)
        time.sleep(self.pause)
        if r.status_code == 204:
            return None
        r.raise_for_status()
        return r.json().get("data")

    def run(self, rid):
        # same cache layout as gmt_bundle.py
        f = self.cache / f"v2_run_{rid}.json"
        if f.exists():
            return json.loads(f.read_text(encoding="utf-8"))
        d = self._get(f"/v2/run/{rid}")
        f.write_text(json.dumps(d), encoding="utf-8")
        return d

    def measurements(self, rid):
        f = self.cache / "measurements" / f"{rid}.json.gz"
        if f.exists():
            with gzip.open(f, "rt", encoding="utf-8") as fh:
                return json.load(fh)
        d = self._get(f"/v1/measurements/single/{rid}") or []
        with gzip.open(f, "wt", encoding="utf-8") as fh:
            json.dump(d, fh)
        return d


def column_for(metric):
    for rx, col, agg in METRIC_MAP:
        if re.match(rx, metric):
            return col, agg
    return None, None


def rank(metric):
    return next((i for i, k in enumerate(SOURCE_RANK) if k in metric), len(SOURCE_RANK))


def phase_spans(run):
    """list of (name, start_us, end_us, is_top) ; flow phases are inside [RUNTIME]"""
    top = {"[BASELINE]", "[INSTALLATION]", "[BOOT]", "[IDLE]", "[RUNTIME]", "[REMOVE]"}
    out = []
    for p in run.get("phases") or []:
        if p.get("start") is not None and p.get("end") is not None:
            out.append((p["name"], p["start"], p["end"], p["name"] in top))
    return out


def label_phase(t_us, spans):
    flow = next((n for n, s, e, top in spans if not top and s <= t_us < e), None)
    if flow:
        return flow
    return next((n for n, s, e, top in spans if top and s <= t_us < e), None)


def scenario_info(run):
    fn = (run.get("filename") or "").replace("\\", "/")
    parts = fn.split("/")
    bench = parts[-2] if len(parts) >= 2 else ""
    dbms = Path(fn).stem
    return fn, bench, dbms


def build_rows(run, meas, window_s, keep_phases):
    spans = phase_spans(run)
    keep = [(n, s, e) for n, s, e, top in spans if top and n in keep_phases]
    if not keep:
        return [], {}
    t0 = min(s for _, s, _ in keep)
    w_us = window_s * 1e6

    # choose one source metric per column
    chosen = {}
    for metric in {row[2] for row in meas}:
        col, agg = column_for(metric)
        if col and (col not in chosen or rank(metric) < rank(chosen[col][0])):
            chosen[col] = (metric, agg)
    metric_to = {m: (c, a) for c, (m, a) in chosen.items()}

    # bins[col][win][detail] -> list of values
    bins = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for detail, t, metric, value, unit in meas:
        if metric not in metric_to or value is None:
            continue
        if not any(s <= t < e for _, s, e in keep):
            continue
        col, _ = metric_to[metric]
        bins[col][int((t - t0) // w_us)][detail].append(float(value))

    def agg_val(col, win):
        agg = chosen[col][1]
        per_detail = bins[col].get(win)
        if not per_detail:
            return None
        if agg == "sum_uj":
            return sum(sum(v) for v in per_detail.values()) / 1e6
        if agg == "sum":
            return sum(sum(v) for v in per_detail.values())
        if agg == "mean_ratio":
            vals = [x for v in per_detail.values() for x in v]
            return sum(vals) / len(vals) / 100.0
        if agg == "mean_ratio_sum_details":
            return sum(sum(v) / len(v) for v in per_detail.values()) / 100.0
        if agg == "mean_hz_over_details":
            means = [sum(v) / len(v) for v in per_detail.values()]
            return sum(means) / len(means) / 1e6
        if agg == "mean_over_details":
            means = [sum(v) / len(v) for v in per_detail.values()]
            return sum(means) / len(means)
        if agg == "mean_sum_details":
            return sum(sum(v) / len(v) for v in per_detail.values())
        vals = [x for v in per_detail.values() for x in v]
        return sum(vals) / len(vals)

    wins = sorted({w for col in bins for w in bins[col]})
    rows = []
    for win in wins:
        mid = t0 + (win + 0.5) * w_us
        row = {"t_s": round(win * window_s, 3), "window_s": window_s, "phase": label_phase(mid, spans)}
        for col in chosen:
            row[col] = agg_val(col, win)
        rows.append(row)

    # drop first/last partial windows of every kept top-phase (energy would be truncated)
    edges = set()
    for _, s, e in keep:
        edges.add(int((s - t0) // w_us))
        edges.add(int((e - t0) // w_us))
    rows = [r_ for r_ in rows if round(r_["t_s"] / window_s) not in edges]

    # baseline power per target from the [BASELINE] phase
    base = {}
    brow = [r_ for r_ in rows if r_["phase"] == "[BASELINE]"]
    for tcol, bcol in (("psu_energy_j", "baseline_psu_w"), ("rapl_cpu_j", "baseline_rapl_cpu_w"),
                       ("rapl_mem_j", "baseline_rapl_mem_w")):
        vals = [r_[tcol] for r_ in brow if r_.get(tcol) is not None]
        base[bcol] = (sum(vals) / len(vals) / window_s) if vals else None
    info = {"chosen_metrics": {c: m for c, (m, _) in chosen.items()}}
    return [{**r_, **base} for r_ in rows], info


def collect_run_ids(args):
    ids = []
    if args.cross:
        cross = json.loads(Path(args.cross).read_text(encoding="utf-8"))
        for s_ in cross.get("scenarios", []):
            ids += s_.get("runs_used", [])[: args.reps]
    if args.digest:
        dig = json.loads(Path(args.digest).read_text(encoding="utf-8"))
        ids += sorted({t["run_id"] for t in dig.get("tasks", []) if t.get("run_id")})
    if args.runs:
        ids += [x.strip() for x in args.runs.split(",") if x.strip()]
    seen, out = set(), []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out[: args.max_runs] if args.max_runs else out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api", default=PUBLIC_API)
    p.add_argument("--cache", default=".gmt_cache", help="same cache dir as gmt_bundle.py")
    p.add_argument("--pause", type=float, default=0.0)
    p.add_argument("--cross")
    p.add_argument("--digest")
    p.add_argument("--runs")
    p.add_argument("--reps", type=int, default=1, help="runs per DBMS-bench scenario taken from --cross")
    p.add_argument("--max-runs", type=int, default=0)
    p.add_argument("--window", type=float, default=1.0, help="window length in seconds")
    p.add_argument("--phases", default=",".join(KEEP_PHASES_DEFAULT),
                   help="top-level phases to export (flow steps are inside [RUNTIME])")
    p.add_argument("--out", default="gmt_dataset.csv.gz")
    a = p.parse_args()

    api = Api(a.api, a.cache, a.pause)
    ids = collect_run_ids(a)
    if not ids:
        sys.exit("no run ids - give --cross, --digest or --runs")
    keep = tuple(x.strip() for x in a.phases.split(","))

    opener = gzip.open if a.out.endswith(".gz") else open
    cols = ID_COLS + FEATURES + TARGETS + CTX
    n_rows, report = 0, []
    with opener(a.out, "wt", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for i, rid in enumerate(ids, 1):
            t_start = time.time()
            try:
                run = api.run(rid) or {}
                meas = api.measurements(rid)
            except requests.RequestException as exc:
                print(f"[{i}/{len(ids)}] {rid[:8]} download failed: {exc}", file=sys.stderr)
                continue
            if not run or not meas:
                print(f"[{i}/{len(ids)}] {rid[:8]} no data", file=sys.stderr)
                continue
            rows, info = build_rows(run, meas, a.window, keep)
            fn, bench, dbms = scenario_info(run)
            ident = {"run_id": rid, "machine_id": run.get("machine_id"),
                     "machine": ((run.get("machine_specs") or {}).get("Hardware Model") or "")[:40],
                     "scenario": fn, "benchmark": bench, "dbms": dbms, "branch": run.get("branch")}
            for r_ in rows:
                w.writerow({**ident, **{k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in r_.items()}})
            n_rows += len(rows)
            report.append({"run_id": rid, "rows": len(rows), **ident, **info})
            print(f"[{i}/{len(ids)}] {rid[:8]} {bench}/{dbms}@{run.get('branch')} machine {run.get('machine_id')}: "
                  f"{len(rows)} windows, metrics {sorted(info.get('chosen_metrics', {}))} ({time.time()-t_start:.0f}s)",
                  file=sys.stderr, flush=True)

    Path(re.sub(r"\.csv(\.gz)?$", "", a.out) + "_runs.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(f"{n_rows} rows from {len(report)} runs -> {a.out}")


if __name__ == "__main__":
    main()
