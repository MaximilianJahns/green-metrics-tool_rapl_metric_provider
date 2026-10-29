#!/usr/bin/env python3
"""
Train a feed-forward neural network (MLP) on energy-logger data.

Uses the same log format, parsing, diffing and feature sets as the
linear-regression script, so both can be run on the same files and compared.

Example:
    ./train_nn.py train.log --predict test.log --features all \
        --target psu_energy_ac_mcp_machine --plot-loss
"""
import re
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader

from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score, mean_absolute_error, mean_absolute_percentage_error
import plotext as plt

TARGET_COL = None  # Will be set by argparse


# --------------------------------------------------------------------------
# Data loading (same format as the linear-regression script)
# --------------------------------------------------------------------------

def parse_monitor_file(path: str | Path):
    """Parse logfile into a DataFrame of relevant metrics."""
    rows = []

    pid0_re = re.compile(
        r"pid=0.*?"
        r"cpu_ns=(\d+)\s+mem=(\d+)\s+instructions=(\d+)\s+wakeups=(\d+)\s+"
        r"diski=(\d+)\s+disko=(\d+)\s+rx=(\d+)\s+tx=(\d+)"
    )
    target_col_re = re.compile(rf"{TARGET_COL}=(\d+)")
    timestamp_re = re.compile(r"timestamp=(\d+)")
    sample_re = re.compile(r"sample_ns=(\d+)")

    with open(path, encoding="utf-8") as f:
        blocks = [b.strip() for b in f.read().split("-------") if b.strip()]

    for block in blocks:
        target = target_col_re.search(block)
        pid0 = pid0_re.search(block)
        timestamp = timestamp_re.search(block)
        sample_ns = sample_re.search(block)

        if target and pid0 and timestamp and sample_ns:
            rows.append({
                TARGET_COL: int(target.group(1)),
                "timestamp": int(timestamp.group(1)),
                "sample_ns": int(sample_ns.group(1)),
                "cpu_ns": int(pid0.group(1)),
                "mem": int(pid0.group(2)),
                "instructions": int(pid0.group(3)),
                "wakeups": int(pid0.group(4)),
                "diski": int(pid0.group(5)),
                "disko": int(pid0.group(6)),
                "rx": int(pid0.group(7)),
                "tx": int(pid0.group(8)),
            })

    return pd.DataFrame(rows)


def select_features(df, features):
    """Add derived features and return (df, feature_list)."""
    # instructions per cpu-ns; guard against division by zero on idle samples
    df["ips"] = (df["instructions"] / df["cpu_ns"].replace(0, np.nan)).fillna(0.0)

    if features == "normal":
        feature_list = ["instructions", "wakeups", "mem"]
    elif features == "extra":
        feature_list = ["instructions", "ips", "wakeups", "rx", "tx"]
    elif features == "all":
        feature_list = ["cpu_ns", "mem", "instructions", "wakeups", "diski", "disko", "rx", "tx"]
    elif features == "idle":
        feature_list = ["wakeups"]
    elif features == "compute":
        feature_list = ["instructions"]
    else:
        raise ValueError(f"Unknown feature set: {features}")

    return df, feature_list


def load_and_prepare(path, features):
    """Parse, diff cumulative counters, and add features. Same steps for train and predict."""
    df = parse_monitor_file(path)
    if len(df) < 2:
        raise ValueError(f"Not enough samples parsed from {path} (got {len(df)}).")

    df_original = df.copy()
    df = df.diff()
    df["timestamp"] = df_original["timestamp"]
    df["sample_ns"] = df_original["sample_ns"]
    df = df.drop(index=0).reset_index(drop=True)

    df, feature_list = select_features(df, features)
    return df, feature_list


def to_arrays(df, feature_list, use_log):
    """Extract X and y as float arrays, optionally log-transformed."""
    X = df[feature_list].to_numpy(dtype=np.float64)
    y = df[TARGET_COL].to_numpy(dtype=np.float64)

    if use_log:
        if (X < 0).any() or (y < 0).any():
            raise ValueError("Negative diffs found (counter reset?). --log requires non-negative values.")
        X = np.log1p(X)
        y = np.log1p(y)

    if not np.isfinite(X).all() or not np.isfinite(y).all():
        raise ValueError("NaN/inf values found in features or target!")

    return X, y


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

class MLP(nn.Module):
    """Plain feed-forward network: [Linear -> ReLU -> Dropout] x N -> Linear(1)."""

    def __init__(self, n_inputs, hidden_sizes, dropout):
        super().__init__()
        layers = []
        prev = n_inputs
        for h in hidden_sizes:
            layers += [nn.Linear(prev, h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        layers.append(nn.Linear(prev, 1))  # single regression output
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x).squeeze(-1)


def train_model(model, X_tr, y_tr, X_val, y_val, args, device):
    """Mini-batch training with Adam, LR scheduling and early stopping on validation loss."""
    train_ds = TensorDataset(torch.tensor(X_tr, dtype=torch.float32),
                             torch.tensor(y_tr, dtype=torch.float32))
    # Shuffling batches is fine; the train/val split itself is time-based.
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)

    X_val_t = torch.tensor(X_val, dtype=torch.float32, device=device)
    y_val_t = torch.tensor(y_val, dtype=torch.float32, device=device)

    loss_fn = nn.HuberLoss() if args.loss == "huber" else nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, factor=0.5, patience=max(1, args.patience // 3)
    )

    best_val = float("inf")
    best_state = None
    epochs_without_improvement = 0
    history = {"train": [], "val": []}

    for epoch in range(1, args.epochs + 1):
        # ---- training pass ----
        model.train()
        total = 0.0
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = loss_fn(model(xb), yb)   # forward pass
            loss.backward()                 # backpropagation
            optimizer.step()                # weight update
            total += loss.item() * len(xb)
        train_loss = total / len(train_ds)

        # ---- validation pass ----
        model.eval()
        with torch.no_grad():
            val_loss = loss_fn(model(X_val_t), y_val_t).item()
        scheduler.step(val_loss)

        history["train"].append(train_loss)
        history["val"].append(val_loss)

        if val_loss < best_val - 1e-7:
            best_val = val_loss
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1

        if epoch == 1 or epoch % args.print_every == 0:
            lr = optimizer.param_groups[0]["lr"]
            print(f"epoch {epoch:4d}  train_loss {train_loss:.5f}  val_loss {val_loss:.5f}  lr {lr:.1e}")

        if epochs_without_improvement >= args.patience:
            print(f"Early stopping at epoch {epoch} (best val_loss {best_val:.5f})")
            break

    model.load_state_dict(best_state)
    return history


def predict(model, X_scaled, y_scaler, use_log, device):
    """Run the model and map predictions back to the original target units."""
    model.eval()
    with torch.no_grad():
        p = model(torch.tensor(X_scaled, dtype=torch.float32, device=device)).cpu().numpy()
    p = y_scaler.inverse_transform(p.reshape(-1, 1)).ravel()
    if use_log:
        p = np.expm1(p)
    return p


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

def wape(y_true, y_pred):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    return np.sum(np.abs(y_true - y_pred)) / np.sum(np.abs(y_true))


def smape(y_true, y_pred, eps=1e-8):
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    denom = np.maximum(np.abs(y_true) + np.abs(y_pred), eps)
    return np.mean(2 * np.abs(y_pred - y_true) / denom)


def print_metrics(title, y_true, y_pred):
    print(f"\n== {title} ==")
    print("MAE:      ", mean_absolute_error(y_true, y_pred))
    print("MAPE (%): ", 100 * mean_absolute_percentage_error(y_true, y_pred))
    print("WAPE (%): ", 100 * wape(y_true, y_pred))
    print("sMAPE (%):", 100 * smape(y_true, y_pred))
    print("R²:       ", r2_score(y_true, y_pred))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def pick_device(name):
    if name != "auto":
        return torch.device(name)
    if torch.cuda.is_available():
        return torch.device("cuda")
    if torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")



# ==========================================================================
# GMT extension (HTW / CASO). Everything above this line and main() below is
# Arne's original code, unchanged. This block only adds a loader for windowed
# GMT data (gmt_dataset.py), extra targets, target modes and grouped splits.
# Model, training loop, scaling and metrics are reused as they are.
# ==========================================================================

GMT_FEATURE_SETS = {
    "cpu": ["cpu_util_pct"],
    "cpu_freq": ["cpu_util_pct", "cpu_freq_mhz"],
    "cluster": ["cpu_util_pct", "cpu_freq_mhz", "temp"],
    "container": ["container_cpu_util_pct", "mem_used_bytes", "disk_read_b", "disk_write_b", "net_b"],
}
GMT_TARGETS = {  # target column(s) -> baseline power column(s)
    "psu_energy_j": (["psu_energy_j"], ["baseline_psu_w"]),
    "rapl_cpu_j": (["rapl_cpu_j"], ["baseline_rapl_cpu_w"]),
    "rapl_cpu_mem_j": (["rapl_cpu_j", "rapl_mem_j"], ["baseline_rapl_cpu_w", "baseline_rapl_mem_w"]),
}


def gmt_load(paths, features, target, target_mode, query=None, phases=None):
    """read one or more gmt_dataset CSVs -> (df with '__target__', '__offset__', '__y_abs__', feature list)"""
    global TARGET_COL
    df = pd.concat([pd.read_csv(p) for p in paths], ignore_index=True)
    if query:
        df = df.query(query)
    if phases:
        keep = [p.strip() for p in phases.split(",")]
        df = df[df["phase"].isin(keep) | (("flow" in keep) & ~df["phase"].astype(str).str.startswith("["))]
    tcols, bcols = GMT_TARGETS[target]
    if features == "all_available":
        cand = [c for s in GMT_FEATURE_SETS.values() for c in s]
        feature_list = [c for c in dict.fromkeys(cand) if c in df and df[c].notna().mean() > 0.9]
    else:
        feature_list = GMT_FEATURE_SETS[features]
    need = feature_list + tcols + ["window_s"] + (bcols if target_mode == "excess" else [])
    missing = [c for c in need if c not in df]
    if missing:
        raise ValueError(f"columns missing in data: {missing}")
    before = len(df)
    df = df.dropna(subset=need).reset_index(drop=True)
    print(f"{len(df)} of {before} windows usable (need {need})")
    y_abs = df[tcols].sum(axis=1)
    offset = (df[bcols].sum(axis=1) * df["window_s"]) if target_mode == "excess" else 0.0
    df["__y_abs__"] = y_abs
    df["__offset__"] = offset
    df["__target__"] = y_abs - offset
    TARGET_COL = "__target__"
    return df, feature_list


def gmt_folds(df, args):
    """yield (name, train_df, val_df)"""
    if args.split == "time":
        # Arne's split: last val_frac of the (run-ordered) table
        n_val = int(len(df) * args.val_frac)
        yield "time", df.iloc[:-n_val].reset_index(drop=True), df.iloc[-n_val:].reset_index(drop=True)
        return
    groups = df[args.group_col].astype(str)
    if args.split == "group":
        val = set(g.strip() for g in args.val_groups.split(","))
        m = groups.isin(val)
        yield f"{args.group_col} in {sorted(val)}", df[~m].reset_index(drop=True), df[m].reset_index(drop=True)
        return
    for g in sorted(groups.unique()):            # leave-one-group-out
        m = groups == g
        yield f"{args.group_col}={g}", df[~m].reset_index(drop=True), df[m].reset_index(drop=True)


def gmt_fit_predict(df_tr, df_val, feats, args, device):
    """Arne's pipeline on one split: scalers, MLP, linear baseline. Returns (mlp_pred, lin_pred) in absolute units."""
    # inner validation for early stopping: time-based tail of the training part, as in the original
    n_es = max(int(len(df_tr) * args.val_frac), 1)
    tr, es = df_tr.iloc[:-n_es], df_tr.iloc[-n_es:]
    X_tr, y_tr = to_arrays(tr, feats, args.log)
    X_es, y_es = to_arrays(es, feats, args.log)
    X_va, _ = to_arrays(df_val, feats, args.log)
    x_scaler = StandardScaler().fit(X_tr)
    y_scaler = StandardScaler().fit(y_tr.reshape(-1, 1))
    Xs = [x_scaler.transform(x) for x in (X_tr, X_es, X_va)]
    ys = [y_scaler.transform(y.reshape(-1, 1)).ravel() for y in (y_tr, y_es)]
    model = MLP(len(feats), args.hidden, args.dropout).to(device)
    train_model(model, Xs[0], ys[0], Xs[1], ys[1], args, device)
    off = df_val["__offset__"].to_numpy(dtype=np.float64)
    mlp = predict(model, Xs[2], y_scaler, args.log, device) + off
    lin = LinearRegression().fit(Xs[0], ys[0])
    lp = y_scaler.inverse_transform(lin.predict(Xs[2]).reshape(-1, 1)).ravel()
    if args.log:
        lp = np.expm1(lp)
    return mlp, lp + off, model, (x_scaler, y_scaler)


def gmt_metrics(y_true, y_pred):
    return {"MAE": float(mean_absolute_error(y_true, y_pred)),
            "MAPE_pct": float(100 * mean_absolute_percentage_error(y_true, y_pred)),
            "WAPE_pct": float(100 * wape(y_true, y_pred)),
            "R2": float(r2_score(y_true, y_pred)) if len(y_true) > 1 else None,
            "total_error_pct": float(100 * (np.sum(y_pred) - np.sum(y_true)) / np.sum(y_true))}


def main_gmt(args):
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = pick_device(args.device)
    feats_name = args.features if args.features in list(GMT_FEATURE_SETS) + ["all_available"] else "cpu"
    if feats_name != args.features:
        print(f"--features {args.features} is a procpower set; using GMT set 'cpu'")
    df, feats = gmt_load([args.logfile], feats_name, args.target, args.target_mode, args.filter, args.phases)
    print(f"features: {feats} | target: {args.target} ({args.target_mode}) | device: {device}")

    results, pooled = [], {"y": [], "mlp": [], "lin": []}
    last = None
    for name, d_tr, d_va in gmt_folds(df, args):
        if len(d_va) == 0 or len(d_tr) < 20:
            continue
        print(f"\n### fold {name}: {len(d_tr)} train / {len(d_va)} validation")
        mlp, lin, model, scalers = gmt_fit_predict(d_tr, d_va, feats, args, device)
        y = d_va["__y_abs__"].to_numpy()
        res = {"fold": name, "n_train": len(d_tr), "n_val": len(d_va),
               "mlp": gmt_metrics(y, mlp), "linear": gmt_metrics(y, lin)}
        results.append(res)
        print_metrics(f"MLP {name}", y, mlp)
        print_metrics(f"Linear {name}", y, lin)
        pooled["y"].append(y); pooled["mlp"].append(mlp); pooled["lin"].append(lin)
        last = (model, scalers)

    if len(results) > 1:
        y = np.concatenate(pooled["y"])
        print_metrics("MLP pooled over all folds", y, np.concatenate(pooled["mlp"]))
        print_metrics("Linear pooled over all folds", y, np.concatenate(pooled["lin"]))
        print(f"\n{'fold':<45}{'MLP WAPE':>10}{'MLP tot%':>10}{'Lin WAPE':>10}{'Lin tot%':>10}")
        for r_ in results:
            print(f"{r_['fold'][:44]:<45}{r_['mlp']['WAPE_pct']:>10.1f}{r_['mlp']['total_error_pct']:>10.1f}"
                  f"{r_['linear']['WAPE_pct']:>10.1f}{r_['linear']['total_error_pct']:>10.1f}")

    # ---- transfer test: train on everything, predict another dataset (e.g. the Windows laptop) ----
    if args.predict:
        print(f"\n### transfer: train on all of {args.logfile}, predict {args.predict}")
        df2, _ = gmt_load([args.predict], feats_name, args.target, args.target_mode, args.predict_filter, args.phases)
        mlp, lin, model, scalers = gmt_fit_predict(df, df2, feats, args, device)
        y2 = df2["__y_abs__"].to_numpy()
        print_metrics(f"MLP on {args.predict}", y2, mlp)
        print_metrics(f"Linear on {args.predict}", y2, lin)
        results.append({"fold": f"transfer->{args.predict}", "n_train": len(df), "n_val": len(df2),
                        "mlp": gmt_metrics(y2, mlp), "linear": gmt_metrics(y2, lin)})
        if args.dump_predictions:
            out = df2[["run_id", "phase", "t_s"] + feats].copy()
            out["y_true"], out["mlp"], out["linear"] = y2, mlp, lin
            out.to_csv(args.dump_predictions, index=False)
            print(f"predictions -> {args.dump_predictions}")
        last = (model, scalers)

    if args.results:
        Path(args.results).write_text(json.dumps({"args": vars(args), "features": feats, "results": results}, indent=1))
        print(f"results -> {args.results}")
    if args.save and last:
        model, (xs, ys) = last
        torch.save({"state_dict": model.state_dict(), "features": feats, "target": args.target,
                    "target_mode": args.target_mode, "hidden": args.hidden, "dropout": args.dropout, "log": args.log,
                    "x_mean": xs.mean_, "x_scale": xs.scale_, "y_mean": ys.mean_, "y_scale": ys.scale_}, args.save)
        print(f"model -> {args.save}")


def main(args):
    global TARGET_COL
    TARGET_COL = args.target

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = pick_device(args.device)

    df, FEATURES = load_and_prepare(args.logfile, args.features)

    if args.dump_diff:
        print(df)

    if args.plot_only:
        plt.clear_data()
        plt.plot(df["timestamp"].tolist(), df[TARGET_COL].tolist(), marker="dot")
        plt.xlabel("Time")
        plt.ylabel(TARGET_COL)
        plt.show()
        return

    # ---- time-based train/validation split (no random shuffling across time) ----
    n_val = int(len(df) * args.val_frac)
    n_train = len(df) - n_val
    if n_val < 1 or n_train < 10:
        raise ValueError(f"Too few samples for a split: {n_train} train / {n_val} val.")
    df_train = df.iloc[:n_train].reset_index(drop=True)
    df_val = df.iloc[n_train:].reset_index(drop=True)
    print(f"Samples: {n_train} train / {n_val} validation  |  features: {FEATURES}  |  device: {device}")

    X_tr, y_tr = to_arrays(df_train, FEATURES, args.log)
    X_val, y_val = to_arrays(df_val, FEATURES, args.log)

    # Scalers are fit on training data only, then reused everywhere.
    # Scaling y matters for NNs: raw energy values are huge and would make training unstable.
    x_scaler = StandardScaler().fit(X_tr)
    y_scaler = StandardScaler().fit(y_tr.reshape(-1, 1))

    X_tr_s, X_val_s = x_scaler.transform(X_tr), x_scaler.transform(X_val)
    y_tr_s = y_scaler.transform(y_tr.reshape(-1, 1)).ravel()
    y_val_s = y_scaler.transform(y_val.reshape(-1, 1)).ravel()

    # ---- build and train the network ----
    model = MLP(len(FEATURES), args.hidden, args.dropout).to(device)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model: {model}\nTrainable parameters: {n_params}\n")

    history = train_model(model, X_tr_s, y_tr_s, X_val_s, y_val_s, args, device)

    val_pred = predict(model, X_val_s, y_scaler, args.log, device)
    print_metrics("MLP on validation split", df_val[TARGET_COL], val_pred)

    # ---- linear baseline on exactly the same data, for comparison ----
    baseline = None
    if not args.no_baseline:
        baseline = LinearRegression().fit(X_tr_s, y_tr_s)
        base_pred = y_scaler.inverse_transform(baseline.predict(X_val_s).reshape(-1, 1)).ravel()
        if args.log:
            base_pred = np.expm1(base_pred)
        print_metrics("Linear baseline on validation split", df_val[TARGET_COL], base_pred)

    if args.plot_loss:
        plt.clear_data()
        plt.plot(history["train"], label="train")
        plt.plot(history["val"], label="val")
        plt.xlabel("Epoch")
        plt.ylabel("Loss (scaled)")
        plt.title("Training curve")
        plt.show()

    # ---- predict on a separate logfile ----
    if args.predict:
        df2, _ = load_and_prepare(args.predict, args.features)
        X2, _ = to_arrays(df2, FEATURES, args.log)
        X2_s = x_scaler.transform(X2)
        y2_true = df2[TARGET_COL]  # always in original units

        predictions = predict(model, X2_s, y_scaler, args.log, device)
        print_metrics(f"MLP on {args.predict}", y2_true, predictions)

        if baseline is not None:
            base2 = y_scaler.inverse_transform(baseline.predict(X2_s).reshape(-1, 1)).ravel()
            if args.log:
                base2 = np.expm1(base2)
            print_metrics(f"Linear baseline on {args.predict}", y2_true, base2)

        if args.dump_predictions:
            out = df2[FEATURES].copy()
            out.insert(0, f"{TARGET_COL}_pred", predictions)
            out.insert(0, TARGET_COL, y2_true)
            print(out)

        if args.dump_top_errors:
            errors = (y2_true - predictions).abs()
            top = df2.loc[errors.nlargest(10).index].copy()
            top.insert(1, "prediction", predictions[top.index])
            print(top)

    if args.save:
        torch.save({
            "state_dict": model.state_dict(),
            "features": FEATURES,
            "target": TARGET_COL,
            "hidden": args.hidden,
            "dropout": args.dropout,
            "log": args.log,
            "x_mean": x_scaler.mean_, "x_scale": x_scaler.scale_,
            "y_mean": y_scaler.mean_, "y_scale": y_scaler.scale_,
        }, args.save)
        print(f"\nModel saved to {args.save}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train an MLP on energy-logger data")
    parser.add_argument("logfile", help="Logfile of energy-logger to use for training")
    parser.add_argument("--predict", help="Logfile to parse for prediction")
    parser.add_argument("--features", choices=["normal", "extra", "compute", "idle", "all"] + list(GMT_FEATURE_SETS) + ["all_available"],
                        default="all", help="Feature set to use")
    parser.add_argument("--target", type=str,
                        choices=["rapl_psys_sum_uj", "rapl_core_sum_uj", "psu_energy_ac_mcp_machine"] + list(GMT_TARGETS),
                        default="psu_energy_ac_mcp_machine")
    parser.add_argument("--log", action="store_true", help="Apply log1p transform to features and target")

    # network / training hyperparameters
    parser.add_argument("--hidden", type=int, nargs="+", default=[64, 64],
                        help="Hidden layer sizes, e.g. --hidden 128 64 32")
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--epochs", type=int, default=500)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--weight-decay", type=float, default=1e-5, help="L2 regularization")
    parser.add_argument("--loss", choices=["mse", "huber"], default="huber")
    parser.add_argument("--patience", type=int, default=30, help="Early-stopping patience in epochs")
    parser.add_argument("--val-frac", type=float, default=0.2,
                        help="Fraction of the (time-ordered) training log held out for validation")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--device", default="auto", help="auto, cpu, cuda or mps")
    parser.add_argument("--print-every", type=int, default=10)

    # output options
    parser.add_argument("--no-baseline", action="store_true", help="Skip the linear regression comparison")
    parser.add_argument("--plot-loss", action="store_true", help="Plot the training curve in the terminal")
    parser.add_argument("--plot-only", action="store_true", help="Plot the training data file and exit")
    parser.add_argument("--dump-diff", action="store_true", help="Dump parsed and diffed data")
    parser.add_argument("--dump-predictions", action="store_true", help="Dump predictions")
    parser.add_argument("--dump-top-errors", action="store_true", help="Dump top errors")
    parser.add_argument("--save", help="Path to save the trained model (e.g. model.pt)")

    # GMT extension options
    parser.add_argument("--format", choices=["procpower", "gmt"], default="procpower",
                        help="procpower = energy-logger log (original), gmt = CSV from gmt_dataset.py")
    parser.add_argument("--target-mode", choices=["absolute", "excess"], default="absolute",
                        help="gmt: excess = learn energy above the machine's baseline power")
    parser.add_argument("--split", choices=["time", "group", "loo"], default="time",
                        help="gmt: time = original tail split, group = hold out --val-groups, loo = leave one group out")
    parser.add_argument("--group-col", default="scenario", help="gmt: column for group/loo split, e.g. dbms, benchmark, machine_id")
    parser.add_argument("--val-groups", default="", help="gmt: comma separated groups held out with --split group")
    parser.add_argument("--filter", default="", help="gmt: pandas query on the training data, e.g. \"machine_id == 13\"")
    parser.add_argument("--predict-filter", default="", help="gmt: pandas query on the --predict data")
    parser.add_argument("--phases", default="", help="gmt: keep only these phases, e.g. flow or [BASELINE],flow")
    parser.add_argument("--results", default="", help="gmt: write all fold metrics as JSON")

    _args = parser.parse_args()
    if _args.format == "gmt":
        if _args.target not in GMT_TARGETS:
            _args.target = "psu_energy_j"
        main_gmt(_args)
    else:
        main(_args)
