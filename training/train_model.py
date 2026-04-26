#!/usr/bin/env python3
"""
Train a neural network on CIC-IDS2017 for ESP32-S3 deployment.
Uses knowledge distillation + quantization-aware training (QAT) + per-channel INT8.
"""

import os
import sys
import math
import numpy as np

# Force line-buffered stdout (so output appears immediately when redirected)
if not sys.stdout.isatty():
    sys.stdout.reconfigure(line_buffering=True)
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE, RandomOverSampler
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
DATA_FILE = "/mnt/ai_memory/datasets/cic_ids2017_flows.parquet"
DATA_2018_DIR = os.path.expanduser(
    "~/.cache/kagglehub/datasets/solarmainframe/ids-intrusion-csv/versions/1"
)
DATA_2019_DIR = os.path.expanduser(
    "~/.cache/kagglehub/datasets/dhoogla/cicddos2019/versions/3"
)

SELECTED_FEATURES = [
    "destination_port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Mean", "Bwd IAT Mean", "Fwd PSH Flags", "SYN Flag Count",
    "RST Flag Count", "ACK Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
]

LABEL_MAP = {
    # CIC-IDS2017 labels
    "BENIGN": "Normal", "Bot": "Botnet", "DDoS": "DDoS",
    "DoS GoldenEye": "DoS", "DoS Hulk": "DoS",
    "DoS Slowhttptest": "DoS", "DoS slowloris": "DoS",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Heartbleed": "DoS", "Infiltration": "Infiltration",
    "PortScan": "PortScan",
    "Web Attack \x96 Brute Force": "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Web Attack \x96 XSS": "WebAttack",
    "Web Attack – Brute Force": "WebAttack",
    "Web Attack – Sql Injection": "WebAttack",
    "Web Attack – XSS": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    # CSE-CIC-IDS2018 labels
    "Benign": "Normal",
    "FTP-BruteForce": "BruteForce", "SSH-Bruteforce": "BruteForce",
    "DoS attacks-GoldenEye": "DoS", "DoS attacks-Slowloris": "DoS",
    "DoS attacks-Hulk": "DoS", "DoS attacks-SlowHTTPTest": "DoS",
    "DDOS attack-HOIC": "DDoS", "DDOS attack-LOIC-UDP": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "Brute Force -Web": "WebAttack", "Brute Force -XSS": "WebAttack",
    "SQL Injection": "WebAttack",
    "Infilteration": "Infiltration",
    "Bot": "Botnet",
    # CIC-DDoS2019 labels (all DDoS variants)
    "DrDoS_DNS": "DDoS", "DrDoS_LDAP": "DDoS", "DrDoS_MSSQL": "DDoS",
    "DrDoS_NTP": "DDoS", "DrDoS_NetBIOS": "DDoS", "DrDoS_SNMP": "DDoS",
    "DrDoS_UDP": "DDoS", "LDAP": "DDoS", "MSSQL": "DDoS",
    "NetBIOS": "DDoS", "Portmap": "DDoS", "Syn": "DDoS",
    "TFTP": "DDoS", "UDP": "DDoS", "UDP-lag": "DDoS",
    "UDPLag": "DDoS", "WebDDoS": "DDoS",
}

# CSE-CIC-IDS2018 uses abbreviated column names — map to CIC-IDS2017 names
RENAME_2018 = {
    "Dst Port": "destination_port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Label": "attack_label",
}

# CIC-DDoS2019 uses slightly different column names
RENAME_2019 = {
    "Fwd Packets Length Total": "Total Length of Fwd Packets",
    "Bwd Packets Length Total": "Total Length of Bwd Packets",
    "Avg Packet Size": "Average Packet Size",
    "Init Fwd Win Bytes": "Init_Win_bytes_forward",
    "Init Bwd Win Bytes": "Init_Win_bytes_backward",
    "Label": "attack_label",
}

CATEGORIES = ["Normal", "DoS", "DDoS", "PortScan", "BruteForce",
              "WebAttack", "Infiltration", "Botnet"]
NUM_FEATURES = len(SELECTED_FEATURES)
NUM_CLASSES = len(CATEGORIES)
LAYER1 = 128
LAYER2 = 64


# ─── Models ──────────────────────────────────────────────────

class TeacherModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(NUM_FEATURES, 256)
        self.fc2 = nn.Linear(256, 128)
        self.fc3 = nn.Linear(128, 64)
        self.fc4 = nn.Linear(64, NUM_CLASSES)
        self.relu = nn.ReLU()
        self.drop1 = nn.Dropout(0.4)
        self.drop2 = nn.Dropout(0.3)
        self.drop3 = nn.Dropout(0.2)

    def forward(self, x):
        x = self.drop1(self.relu(self.fc1(x)))
        x = self.drop2(self.relu(self.fc2(x)))
        x = self.drop3(self.relu(self.fc3(x)))
        return self.fc4(x)


class IDSModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(NUM_FEATURES, LAYER1)
        self.fc2 = nn.Linear(LAYER1, LAYER2)
        self.fc3 = nn.Linear(LAYER2, NUM_CLASSES)
        self.relu = nn.ReLU()
        self.drop1 = nn.Dropout(0.3)
        self.drop2 = nn.Dropout(0.2)

    def forward(self, x):
        x = self.drop1(self.relu(self.fc1(x)))
        x = self.drop2(self.relu(self.fc2(x)))
        return self.fc3(x)


# ─── Fake Quantization Helpers (for QAT) ─────────────────────

def _fake_quant(x, scale):
    """Simulate quantization with straight-through estimator."""
    s = max(scale, 1e-10)
    x_q = torch.clamp(torch.round(x / s), -128, 127) * s
    return x + (x_q - x).detach()


def _fake_quant_weight_perchannel(w):
    """Per-channel weight fake quantization with STE."""
    scales = (w.detach().abs().amax(dim=1, keepdim=True) / 127.0).clamp(min=1e-10)
    w_q = torch.clamp(torch.round(w / scales), -128, 127) * scales
    return w + (w_q - w).detach()


def _qat_forward(model, x, in_s, l1_s, l2_s, training=False):
    """Forward pass with simulated INT8 quantization at every boundary."""
    x = _fake_quant(x, in_s)
    x = F.linear(x, _fake_quant_weight_perchannel(model.fc1.weight), model.fc1.bias)
    x = F.relu(x)
    x = _fake_quant(x, l1_s)
    if training: x = F.dropout(x, p=0.3)
    x = F.linear(x, _fake_quant_weight_perchannel(model.fc2.weight), model.fc2.bias)
    x = F.relu(x)
    x = _fake_quant(x, l2_s)
    if training: x = F.dropout(x, p=0.2)
    x = F.linear(x, _fake_quant_weight_perchannel(model.fc3.weight), model.fc3.bias)
    return x


# ─── Data Loading ────────────────────────────────────────────

def _load_one_csv(args):
    """Load a single 2018 CSV — only reads needed columns to save RAM."""
    path, cols_2018, max_rows = args
    import pyarrow.csv as pcsv
    name = os.path.basename(path)
    try:
        # Peek at header to find which needed columns actually exist
        with open(path, 'r', errors='replace') as fh:
            header_line = fh.readline()
        actual_cols = [c.strip() for c in header_line.split(',')]
        col_set = set(cols_2018)
        keep_cols = [c for c in actual_cols if c.strip() in col_set]
        if "Label" not in keep_cols:
            return name, None, "no Label column"

        tbl = pcsv.read_csv(
            path,
            read_options=pcsv.ReadOptions(block_size=4 << 20),
            convert_options=pcsv.ConvertOptions(
                include_columns=keep_cols,  # only read what we need — huge RAM saving
                strings_can_be_null=True,
            ),
        )
        if tbl.num_rows > max_rows:
            tbl = tbl.slice(0, max_rows)
        df = tbl.to_pandas()
        del tbl
        df.columns = [c.strip() for c in df.columns]
        df.rename(columns=RENAME_2018, inplace=True)
        if "attack_label" not in df.columns:
            return name, None, "no label after rename"
        df = df[df["attack_label"].isin(LABEL_MAP.keys())]
        return name, df, f"{len(df):,} rows"
    except Exception as e:
        return name, None, str(e)


def load_data():
    import gc
    print("[1/9] Loading datasets...")
    needed = SELECTED_FEATURES + ["attack_label"]
    all_frames = []

    # ── CIC-IDS2017 ──
    MAX_2017_ROWS = 500_000
    print("  Loading CIC-IDS2017 parquet...")
    df_2017 = pd.read_parquet(DATA_FILE, columns=needed)
    if len(df_2017) > MAX_2017_ROWS:
        df_2017 = df_2017.sample(n=MAX_2017_ROWS, random_state=42)
    print(f"    2017: {len(df_2017):,} rows")
    all_frames.append(df_2017)
    del df_2017; gc.collect()

    # ── CSE-CIC-IDS2018 ──
    rename_rev = {v: k for k, v in RENAME_2018.items()}
    cols_2018 = [rename_rev.get(feat, feat) for feat in SELECTED_FEATURES] + ["Label"]
    MAX_ROWS_PER_CSV = 150_000

    if os.path.isdir(DATA_2018_DIR):
        import glob
        csvs = sorted(glob.glob(os.path.join(DATA_2018_DIR, "*.csv")))
        print(f"  Loading CSE-CIC-IDS2018 ({len(csvs)} files, max {MAX_ROWS_PER_CSV:,}/file)...")
        for path in csvs:
            name, df_csv, msg = _load_one_csv((path, cols_2018, MAX_ROWS_PER_CSV))
            print(f"    {name}: {msg}")
            if df_csv is not None and len(df_csv) > 0:
                keep = [c for c in needed if c in df_csv.columns]
                all_frames.append(df_csv[keep])
            del df_csv; gc.collect()

    # ── CIC-DDoS2019 ──
    if os.path.isdir(DATA_2019_DIR):
        import glob
        parquets = sorted(glob.glob(os.path.join(DATA_2019_DIR, "*.parquet")))
        print(f"  Loading CIC-DDoS2019 ({len(parquets)} parquet files)...")
        for path in parquets:
            name = os.path.basename(path)
            try:
                df_pq = pd.read_parquet(path)
                df_pq.rename(columns=RENAME_2019, inplace=True)
                if "destination_port" not in df_pq.columns:
                    df_pq["destination_port"] = 0.0
                if "attack_label" not in df_pq.columns:
                    print(f"    {name}: no label, skip")
                    continue
                df_pq = df_pq[df_pq["attack_label"].isin(LABEL_MAP.keys())]
                keep = [c for c in needed if c in df_pq.columns]
                df_pq = df_pq[keep]
                print(f"    {name}: {len(df_pq):,} rows")
                if len(df_pq) > 0:
                    all_frames.append(df_pq)
            except Exception as e:
                print(f"    {name}: ERROR {e}")

    # ── Combine all datasets ──
    common = sorted(set.intersection(*[set(f.columns) for f in all_frames]))
    common = [c for c in needed if c in common]
    df = pd.concat([f[common] for f in all_frames], ignore_index=True)
    n_datasets = len(set(type(f).__name__ for f in all_frames))
    print(f"  Combined: {len(df):,} total rows from {len(all_frames)} chunks")
    del all_frames; gc.collect()
    return df


def preprocess(df):
    print("[2/9] Preprocessing...")
    df["category"] = df["attack_label"].map(LABEL_MAP)
    df = df.dropna(subset=["category"])
    X = df[SELECTED_FEATURES].copy()
    X = X.apply(lambda col: col.astype(float) if col.dtype == object else col)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    y = np.array(df["category"].values)
    print(f"  Clean rows: {len(X):,}")
    for cat in CATEGORIES:
        print(f"    {cat}: {(y == cat).sum():,}")
    return X.values.astype(np.float32), y


def balance(X, y, max_per_class=50000, min_per_class=5000):
    print("[3/9] Balancing...")
    cat2idx = {c: i for i, c in enumerate(CATEGORIES)}
    y_int = np.array([cat2idx[c] for c in y])
    indices = []
    for cat in CATEGORIES:
        idx = np.where(y_int == cat2idx[cat])[0]
        if len(idx) > max_per_class:
            idx = np.random.choice(idx, max_per_class, replace=False)
        indices.extend(idx)
    np.random.shuffle(indices)
    X_bal, y_bal = X[indices], y_int[indices]

    class_counts = {i: int((y_bal == i).sum()) for i in range(NUM_CLASSES)}
    tiny_target = {i: max(c, 6) for i, c in class_counts.items()}
    if any(tiny_target[i] > class_counts[i] for i in range(NUM_CLASSES)):
        ros = RandomOverSampler(sampling_strategy=tiny_target, random_state=42)
        X_bal, y_bal = ros.fit_resample(X_bal, y_bal)

    smote_target = {i: max(int((y_bal == i).sum()), min_per_class) for i in range(NUM_CLASSES)}
    smote = SMOTE(random_state=42, k_neighbors=5)
    X_bal, y_bal = smote.fit_resample(X_bal, y_bal)

    idx2cat = {i: c for c, i in cat2idx.items()}
    y_str = np.array([idx2cat[i] for i in y_bal])
    print(f"  Balanced: {len(X_bal):,}")
    return X_bal.astype(np.float32), y_str


# Backward-direction feature indices — always 0 on ESP32 (hook only sees AP→out direction)
BWD_INDICES = [3, 5, 9, 10, 11, 19, 24, 27, 29]

def zero_bwd_features(X):
    X = X.copy()
    X[:, BWD_INDICES] = 0.0
    return X

def compute_class_weights(y_train, fp_multiplier=4.0):
    """Inverse-frequency weights with extra penalty for Normal FP.

    fp_multiplier: how much more to penalize misclassifying Normal traffic.
    Higher = fewer false positives, possibly more missed attacks.
    """
    cat2idx = {c: i for i, c in enumerate(CATEGORIES)}
    y_int = np.array([cat2idx[c] for c in y_train])
    counts = np.bincount(y_int, minlength=NUM_CLASSES).astype(float)
    weights = 1.0 / (counts + 1e-6)
    weights[0] *= fp_multiplier  # index 0 = Normal — penalize FP heavily
    weights = weights / weights.sum() * NUM_CLASSES
    print(f"  Class weights: { {CATEGORIES[i]: f'{weights[i]:.3f}' for i in range(NUM_CLASSES)} }")
    return torch.FloatTensor(weights)


# ─── Training ────────────────────────────────────────────────

def train_teacher(X_train, y_train, X_val, y_val):
    print("[4/9] Training teacher (30→256→128→64→8)...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"  Device: {device}")
    cat2idx = {c: i for i, c in enumerate(CATEGORIES)}
    y_tr = np.array([cat2idx[c] for c in y_train])
    y_va = np.array([cat2idx[c] for c in y_val])

    train_dl = DataLoader(TensorDataset(
        torch.FloatTensor(X_train).to(device), torch.LongTensor(y_tr).to(device)),
        batch_size=2048, shuffle=True)
    val_dl = DataLoader(TensorDataset(
        torch.FloatTensor(X_val).to(device), torch.LongTensor(y_va).to(device)),
        batch_size=4096)

    teacher = TeacherModel().to(device)
    opt = torch.optim.AdamW(teacher.parameters(), lr=0.001, weight_decay=1e-4)
    cw = compute_class_weights(y_train).to(device)
    loss_fn = nn.CrossEntropyLoss(weight=cw, label_smoothing=0.1)
    num_epochs, warmup = 100, 5
    lr_fn = lambda e: (e+1)/warmup if e < warmup else 0.5*(1+math.cos(math.pi*(e-warmup)/(num_epochs-warmup)))
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lr_fn)
    best_acc, best_state, patience = 0, None, 0

    for epoch in range(num_epochs):
        teacher.train()
        c = t = 0
        for xb, yb in train_dl:
            opt.zero_grad(); out = teacher(xb); loss_fn(out, yb).backward(); opt.step()
            c += (out.argmax(1)==yb).sum().item(); t += len(xb)
        teacher.eval()
        vc = vt = 0
        with torch.no_grad():
            for xb, yb in val_dl: vc += (teacher(xb).argmax(1)==yb).sum().item(); vt += len(xb)
        va = vc/vt; sched.step()
        if epoch%10==0 or va>best_acc: print(f"  Epoch {epoch:3d}: train={c/t:.4f} val={va:.4f}")
        if va > best_acc:
            best_acc = va; best_state = {k:v.cpu().clone() for k,v in teacher.state_dict().items()}; patience = 0
        else: patience += 1
        if patience >= 20: print(f"  Early stop {epoch}"); break

    teacher.load_state_dict(best_state); teacher.cpu().eval()
    print(f"  Teacher val: {best_acc:.4f} | params: {sum(p.numel() for p in teacher.parameters()):,}")
    return teacher


def train_student_distilled(X_train, y_train, X_val, y_val, teacher, T=4.0, alpha=0.7):
    print(f"[5/9] Distilling student (T={T}, α={alpha})...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    cat2idx = {c: i for i, c in enumerate(CATEGORIES)}
    y_tr = np.array([cat2idx[c] for c in y_train])
    y_va = np.array([cat2idx[c] for c in y_val])

    train_dl = DataLoader(TensorDataset(
        torch.FloatTensor(X_train).to(device), torch.LongTensor(y_tr).to(device)),
        batch_size=2048, shuffle=True)
    val_dl = DataLoader(TensorDataset(
        torch.FloatTensor(X_val).to(device), torch.LongTensor(y_va).to(device)),
        batch_size=4096)

    student = IDSModel().to(device)
    teacher = teacher.to(device).eval()
    opt = torch.optim.AdamW(student.parameters(), lr=0.001, weight_decay=1e-4)
    cw = compute_class_weights(y_train).to(device)
    num_epochs, warmup = 100, 5
    lr_fn = lambda e: (e+1)/warmup if e < warmup else 0.5*(1+math.cos(math.pi*(e-warmup)/(num_epochs-warmup)))
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lr_fn)
    best_acc, best_state, patience = 0, None, 0

    for epoch in range(num_epochs):
        student.train(); c = t = 0
        for xb, yb in train_dl:
            opt.zero_grad(); s_out = student(xb)
            with torch.no_grad(): t_out = teacher(xb)
            soft = F.kl_div(F.log_softmax(s_out/T,1), F.softmax(t_out/T,1), reduction='batchmean')*(T**2)
            hard = F.cross_entropy(s_out, yb, weight=cw, label_smoothing=0.1)
            (alpha*soft + (1-alpha)*hard).backward(); opt.step()
            c += (s_out.argmax(1)==yb).sum().item(); t += len(xb)
        student.eval(); vc = vt = 0
        with torch.no_grad():
            for xb, yb in val_dl: vc += (student(xb).argmax(1)==yb).sum().item(); vt += len(xb)
        va = vc/vt; sched.step()
        if epoch%10==0 or va>best_acc: print(f"  Epoch {epoch:3d}: train={c/t:.4f} val={va:.4f}")
        if va > best_acc:
            best_acc = va; best_state = {k:v.cpu().clone() for k,v in student.state_dict().items()}; patience = 0
        else: patience += 1
        if patience >= 20: print(f"  Early stop {epoch}"); break

    student.load_state_dict(best_state); student.cpu().eval()
    print(f"  Student val: {best_acc:.4f} | params: {sum(p.numel() for p in student.parameters()):,}")
    return student


def _calibrate_scales(model, X_cal, device):
    """Get activation scales from calibration data."""
    model.eval()
    st = model.state_dict()
    with torch.no_grad():
        x = torch.FloatTensor(X_cal).to(device)
        in_s = x.abs().max().item() / 127.0
        l1 = torch.relu(x @ st['fc1.weight'].to(device).t() + st['fc1.bias'].to(device))
        l1_s = l1.abs().max().item() / 127.0
        l2 = torch.relu(l1 @ st['fc2.weight'].to(device).t() + st['fc2.bias'].to(device))
        l2_s = l2.abs().max().item() / 127.0
    return max(in_s, 1e-10), max(l1_s, 1e-10), max(l2_s, 1e-10)


def qat_finetune(model, X_train, y_train, X_val, y_val, X_cal):
    """Quantization-aware fine-tuning: model learns to tolerate INT8 noise."""
    print("[7/9] Quantization-aware training (QAT)...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = model.to(device)

    in_s, l1_s, l2_s = _calibrate_scales(model, X_cal, device)
    print(f"  Scales: input={in_s:.6f} l1={l1_s:.6f} l2={l2_s:.6f}")

    cat2idx = {c: i for i, c in enumerate(CATEGORIES)}
    y_tr = np.array([cat2idx[c] for c in y_train])
    y_va = np.array([cat2idx[c] for c in y_val])

    train_dl = DataLoader(TensorDataset(
        torch.FloatTensor(X_train).to(device), torch.LongTensor(y_tr).to(device)),
        batch_size=2048, shuffle=True)
    val_dl = DataLoader(TensorDataset(
        torch.FloatTensor(X_val).to(device), torch.LongTensor(y_va).to(device)),
        batch_size=4096)

    opt = torch.optim.AdamW(model.parameters(), lr=0.0002, weight_decay=1e-5)
    cw = compute_class_weights(y_train).to(device)
    loss_fn = nn.CrossEntropyLoss(weight=cw)

    num_epochs = 40
    best_acc, best_state, patience = 0, None, 0

    for epoch in range(num_epochs):
        model.train(); c = t = 0
        for xb, yb in train_dl:
            opt.zero_grad()
            out = _qat_forward(model, xb, in_s, l1_s, l2_s, training=True)
            loss_fn(out, yb).backward(); opt.step()
            c += (out.argmax(1)==yb).sum().item(); t += len(xb)

        model.eval(); vc = vt = 0
        with torch.no_grad():
            for xb, yb in val_dl:
                out = _qat_forward(model, xb, in_s, l1_s, l2_s, training=False)
                vc += (out.argmax(1)==yb).sum().item(); vt += len(xb)

        va = vc/vt
        if epoch%5==0 or va>best_acc:
            print(f"  QAT Epoch {epoch:3d}: train={c/t:.4f} val_q={va:.4f}")
        if va > best_acc:
            best_acc = va; best_state = {k:v.cpu().clone() for k,v in model.state_dict().items()}; patience = 0
        else: patience += 1
        if patience >= 15: print(f"  QAT early stop {epoch}"); break

        # Re-calibrate scales every 10 epochs (model weights change → ranges change)
        if (epoch + 1) % 10 == 0:
            in_s, l1_s, l2_s = _calibrate_scales(model, X_cal, device)

    model.load_state_dict(best_state); model.cpu().eval()
    print(f"  QAT best val accuracy: {best_acc:.4f}")
    return model


# ─── Evaluation ──────────────────────────────────────────────

def evaluate(model, X_test, y_test, title="Float32"):
    print(f"[6/9] Evaluating ({title})...")
    cat2idx = {c: i for i, c in enumerate(CATEGORIES)}
    y_true = np.array([cat2idx[c] for c in y_test])
    with torch.no_grad():
        preds = model(torch.FloatTensor(X_test)).argmax(1).numpy()
    report = classification_report(y_true, preds, target_names=CATEGORIES, digits=3, zero_division=0)
    print(report)
    cm = confusion_matrix(y_true, preds)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=CATEGORIES, yticklabels=CATEGORIES)
    plt.title(f"GuardNet IDS - {title}")
    plt.ylabel("True"); plt.xlabel("Predicted"); plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "confusion_matrix.png"), dpi=150)


# ─── INT8 Per-Channel Quantization ──────────────────────────

def calibrate_and_quantize(model, X_cal, X_test, y_test):
    print("[8/9] Per-channel INT8 quantization...")
    model.eval()
    state = model.state_dict()

    with torch.no_grad():
        x = torch.FloatTensor(X_cal)
        input_abs_max = x.abs().max().item()
        l1_out = torch.relu(x @ state['fc1.weight'].t() + state['fc1.bias'])
        l1_abs_max = l1_out.abs().max().item()
        l2_out = torch.relu(l1_out @ state['fc2.weight'].t() + state['fc2.bias'])
        l2_abs_max = l2_out.abs().max().item()

    def sym_scale(v): return v / 127.0 if v > 1e-8 else 1e-8 / 127.0

    input_scale = sym_scale(input_abs_max)
    l1_output_scale = sym_scale(l1_abs_max)
    l2_output_scale = sym_scale(l2_abs_max)

    def quant_w_pc(w):
        out_size = w.shape[0]
        w_q = torch.zeros_like(w, dtype=torch.int8)
        scales = torch.zeros(out_size)
        for o in range(out_size):
            s = sym_scale(w[o].abs().max().item())
            w_q[o] = torch.clamp(torch.round(w[o] / s), -128, 127).to(torch.int8)
            scales[o] = s
        return w_q, scales

    w1_q, w1_s = quant_w_pc(state['fc1.weight'])
    w2_q, w2_s = quant_w_pc(state['fc2.weight'])
    w3_q, w3_s = quant_w_pc(state['fc3.weight'])

    b1_q = torch.zeros(LAYER1, dtype=torch.int32)
    for o in range(LAYER1):
        b1_q[o] = int(round(state['fc1.bias'][o].item() / (input_scale * w1_s[o].item())))
    b2_q = torch.zeros(LAYER2, dtype=torch.int32)
    for o in range(LAYER2):
        b2_q[o] = int(round(state['fc2.bias'][o].item() / (l1_output_scale * w2_s[o].item())))
    b3_q = torch.zeros(NUM_CLASSES, dtype=torch.int32)
    for o in range(NUM_CLASSES):
        b3_q[o] = int(round(state['fc3.bias'][o].item() / (l2_output_scale * w3_s[o].item())))

    l1_rescale = (input_scale * w1_s) / l1_output_scale
    l2_rescale = (l1_output_scale * w2_s) / l2_output_scale
    l3_dequant = l2_output_scale * w3_s

    quant = {
        'input_scale': input_scale,
        'w1_q': w1_q, 'b1_q': b1_q, 'l1_rescale': l1_rescale,
        'w2_q': w2_q, 'b2_q': b2_q, 'l2_rescale': l2_rescale,
        'w3_q': w3_q, 'b3_q': b3_q, 'l3_dequant': l3_dequant,
    }

    print(f"  Activation scales: input={input_scale:.6f} l1={l1_output_scale:.6f} l2={l2_output_scale:.6f}")

    float_bytes = sum(p.numel() * 4 for p in model.parameters())
    int8_bytes = (w1_q.numel() + w2_q.numel() + w3_q.numel()) + \
                 (b1_q.numel() + b2_q.numel() + b3_q.numel()) * 4 + \
                 (LAYER1 + LAYER2 + NUM_CLASSES) * 4
    print(f"  Float32: {float_bytes/1024:.1f} KB → INT8: {int8_bytes/1024:.1f} KB ({float_bytes/int8_bytes:.1f}x)")

    _verify_int8(model, quant, X_test, y_test)
    return quant


def _simulate_int8(x_np, quant):
    x = torch.FloatTensor(x_np)
    x_q = torch.clamp(torch.round(x / quant['input_scale']), -128, 127).to(torch.int64)

    w1 = quant['w1_q'].to(torch.int64); b1 = quant['b1_q'].to(torch.int64)
    acc1 = x_q @ w1.t() + b1.unsqueeze(0)
    acc1 = torch.clamp(acc1, min=0)
    l1 = torch.clamp(torch.round(acc1.float() * quant['l1_rescale'].unsqueeze(0)), -128, 127).to(torch.int64)

    w2 = quant['w2_q'].to(torch.int64); b2 = quant['b2_q'].to(torch.int64)
    acc2 = l1 @ w2.t() + b2.unsqueeze(0)
    acc2 = torch.clamp(acc2, min=0)
    l2 = torch.clamp(torch.round(acc2.float() * quant['l2_rescale'].unsqueeze(0)), -128, 127).to(torch.int64)

    w3 = quant['w3_q'].to(torch.int64); b3 = quant['b3_q'].to(torch.int64)
    acc3 = l2 @ w3.t() + b3.unsqueeze(0)
    return acc3.float() * quant['l3_dequant'].unsqueeze(0)


def _verify_int8(model, quant, X_test, y_test):
    cat2idx = {c: i for i, c in enumerate(CATEGORIES)}
    y_true = np.array([cat2idx[c] for c in y_test])

    with torch.no_grad():
        float_preds = model(torch.FloatTensor(X_test)).argmax(1).numpy()
    float_acc = (float_preds == y_true).mean()

    int8_out = _simulate_int8(X_test, quant)
    int8_preds = int8_out.argmax(1).numpy()
    int8_acc = (int8_preds == y_true).mean()
    agreement = (float_preds == int8_preds).mean()

    print(f"  Float32 accuracy: {float_acc*100:.1f}%")
    print(f"  INT8 accuracy:    {int8_acc*100:.1f}%")
    print(f"  Agreement:        {agreement*100:.1f}%")
    print(f"  Accuracy drop:    {(float_acc-int8_acc)*100:.2f}%")


# ─── Export ──────────────────────────────────────────────────

def export_int8_header(quant, scaler_min, scaler_max):
    print("[9/9] Exporting INT8 C header...")

    def arr_i8(name, arr):
        flat = arr.flatten().numpy()
        lines = [f"static const int8_t {name}[{len(flat)}] = {{"]
        for i in range(0, len(flat), 16):
            lines.append("    " + ", ".join(f"{int(v)}" for v in flat[i:i+16]) + ",")
        lines.append("};"); return "\n".join(lines)

    def arr_i32(name, arr):
        flat = (arr.flatten().numpy() if isinstance(arr, torch.Tensor) else np.array(arr).flatten())
        lines = [f"static const int32_t {name}[{len(flat)}] = {{"]
        for i in range(0, len(flat), 8):
            lines.append("    " + ", ".join(f"{int(v)}" for v in flat[i:i+8]) + ",")
        lines.append("};"); return "\n".join(lines)

    def arr_f(name, data):
        flat = data.flatten().numpy() if isinstance(data, torch.Tensor) else np.array(data).flatten()
        lines = [f"static const float {name}[{len(flat)}] = {{"]
        for i in range(0, len(flat), 8):
            lines.append("    " + ", ".join(f"{v:.10f}f" for v in flat[i:i+8]) + ",")
        lines.append("};"); return "\n".join(lines)

    header = f"""// Auto-generated by train_model.py — DO NOT EDIT
// GuardNet IDS — Per-channel INT8 quantized, knowledge-distilled, QAT fine-tuned
#ifndef MODEL_DATA_H
#define MODEL_DATA_H
#include <stdint.h>

#define NUM_FEATURES {NUM_FEATURES}
#define NUM_CLASSES {NUM_CLASSES}
#define LAYER1_SIZE {LAYER1}
#define LAYER2_SIZE {LAYER2}

static const char* CATEGORY_NAMES[NUM_CLASSES] = {{
    {', '.join(f'"{c}"' for c in CATEGORIES)}
}};

// MinMax scaler
{arr_f("scaler_min", scaler_min)}
{arr_f("scaler_max", scaler_max)}

// Quantization params
static const float q_input_scale = {quant['input_scale']:.10f}f;
{arr_f("q_l1_rescale", quant['l1_rescale'])}
{arr_f("q_l2_rescale", quant['l2_rescale'])}
{arr_f("q_l3_dequant", quant['l3_dequant'])}

// Layer 1: {NUM_FEATURES}→{LAYER1}
{arr_i8("w1_q", quant['w1_q'])}
{arr_i32("b1_q", quant['b1_q'])}

// Layer 2: {LAYER1}→{LAYER2}
{arr_i8("w2_q", quant['w2_q'])}
{arr_i32("b2_q", quant['b2_q'])}

// Layer 3: {LAYER2}→{NUM_CLASSES}
{arr_i8("w3_q", quant['w3_q'])}
{arr_i32("b3_q", quant['b3_q'])}

#endif
"""
    for path in [os.path.join(OUTPUT_DIR, "model_data.h"),
                 os.path.join(os.path.dirname(__file__), "..", "firmware", "main", "model_data.h")]:
        with open(path, "w") as f: f.write(header)
        print(f"  Written {path}")

    total = (quant['w1_q'].numel()+quant['w2_q'].numel()+quant['w3_q'].numel()) + \
            (quant['b1_q'].numel()+quant['b2_q'].numel()+quant['b3_q'].numel())*4 + \
            (LAYER1+LAYER2+NUM_CLASSES)*4
    print(f"  Total: {total:,} bytes ({total/1024:.1f} KB)")


# ─── Main ────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    np.random.seed(42); torch.manual_seed(42)

    ds = load_data()
    X, y = preprocess(ds)
    X, y = balance(X, y)

    # Zero backward features BEFORE scaler fit — ESP32 only captures fwd direction.
    # This ensures scaler range for bwd features is [0,0], matching runtime behaviour.
    X = zero_bwd_features(X)
    print(f"  Zeroed {len(BWD_INDICES)} backward features (indices {BWD_INDICES})")

    scaler = MinMaxScaler()
    X = scaler.fit_transform(X)
    scaler_min = scaler.data_min_.astype(np.float32)
    scaler_max = scaler.data_max_.astype(np.float32)

    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)
    print(f"  Split: {len(X_train):,} / {len(X_val):,} / {len(X_test):,}")

    teacher = train_teacher(X_train, y_train, X_val, y_val)
    student = train_student_distilled(X_train, y_train, X_val, y_val, teacher)
    evaluate(student, X_test, y_test, "Distilled Float32")

    # QAT: fine-tune with simulated quantization noise
    student = qat_finetune(student, X_train, y_train, X_val, y_val, X_val)

    # Final quantization + verification
    quant = calibrate_and_quantize(student, X_val, X_test, y_test)
    export_int8_header(quant, scaler_min, scaler_max)

    torch.save(teacher.state_dict(), os.path.join(OUTPUT_DIR, "teacher_model.pt"))
    torch.save(student.state_dict(), os.path.join(OUTPUT_DIR, "guardnet_model.pt"))
    print("\nDone! QAT INT8 model ready for ESP32-S3.")


if __name__ == "__main__":
    main()
