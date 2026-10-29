# Energy model (CASO AP3) – MLP on GMT data

Arne's MLP from `green-kernel/procpower` (branch `deep-learning`, `tools/train_nn.py`, commit 042c49f),
extended to train on Green Metrics Tool measurements and to test transfer to other machines.

| File | Purpose |
|---|---|
| `train_nn_original.py` | Arne's script, untouched (reference) |
| `train_nn.py` | same model, training loop and metrics; adds `--format gmt`, GMT targets, target modes and grouped splits |
| `gmt_dataset.py` | exports GMT runs as a windowed table (one row = one window of one run) |

`python train_nn.py <log> --format procpower ...` behaves exactly like the original.

## 1. Reproduce the original

```
python train_nn.py M2-fixed-frequency-mixed-workload-new-with-MCP.log ^
  --predict M2-fixed-frequency-mixed-workload-new-with-MCP-2.log --features all --target psu_energy_ac_mcp_machine
```
Reference result (2026-10-29): MLP MAPE 53 %, WAPE 59 %, R² −45 on the second log.

## 2. Export GMT data

Uses the same cache (`.gmt_cache`) as `gmt_bundle.py`. Measurements are a few MB per run.

```
:: DBMS-bench on the cluster, 1 run per scenario (60 runs)
python energy_model\gmt_dataset.py --cross cross_benchmark.json --reps 1 --out data_cluster.csv.gz

:: own runs from a local GMT (Windows runtime)
python energy_model\gmt_dataset.py --api http://api.green-coding.internal:9142 --runs <id>,<id>,<id> --out data_laptop.csv.gz
```

Columns: `run_id, machine_id, scenario, benchmark, dbms, branch, phase, t_s`, features
`cpu_util_pct, container_cpu_util_pct, cpu_freq_mhz, temp, mem_used_bytes, disk_read_b, disk_write_b, net_b`,
targets `psu_energy_j, rapl_cpu_j, rapl_mem_j`, context `window_s, baseline_*_w`.
Each column takes exactly one source metric (e.g. RAPL msr > emi > scaphandre, never summed).

## 3. Train and evaluate

| Option | Meaning |
|---|---|
| `--features cpu \| cpu_freq \| cluster \| container \| all_available` | feature sets of the GMT table |
| `--target psu_energy_j \| rapl_cpu_j \| rapl_cpu_mem_j` | AC at the plug or RAPL package (+DRAM) |
| `--target-mode absolute \| excess` | excess = learn energy above the machine's own baseline power |
| `--split time` | original: last 20 % of the table |
| `--split loo --group-col dbms` | leave one group out (dbms, benchmark, scenario, branch, machine_id) |
| `--split group --group-col machine_id --val-groups 15` | hold out explicit groups |
| `--filter "machine_id == 13"`, `--phases flow` | subset the data |
| `--predict other.csv.gz` | train on everything, predict another dataset (transfer test) |
| `--results r.json`, `--dump-predictions p.csv` | write metrics / predictions |

Metrics are always reported on absolute energy. Larger batches speed up CPU training a lot
(`--batch-size 512`); model and early stopping are unchanged.

```
python energy_model\train_nn.py data_cluster.csv.gz --format gmt --features cpu --target rapl_cpu_j ^
  --split loo --group-col dbms --batch-size 512 --results loo_dbms.json
```

## 4. Transfer test on a Windows laptop

Train on cluster data with `rapl_cpu_j` (same scope as the laptop's EMI RAPL) and only features that
exist on both systems (`--features cpu`). Compare absolute vs. excess mode and against a model trained
on the laptop itself (upper bound).

```
python energy_model\train_nn.py data_cluster.csv.gz --format gmt --features cpu --target rapl_cpu_j ^
  --target-mode excess --predict data_laptop.csv.gz --dump-predictions laptop_pred.csv --results transfer.json
python energy_model\train_nn.py data_laptop.csv.gz --format gmt --features cpu --target rapl_cpu_j ^
  --split loo --group-col run_id --results laptop_self.json
```

Known limits: DBMS-bench runs on the cluster record only system CPU utilization, CPU frequency and
temperature (no memory/disk/network); `custom_*` work metrics (energy per unit of work) are not exported yet.
