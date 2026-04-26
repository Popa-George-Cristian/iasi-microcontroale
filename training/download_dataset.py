#!/usr/bin/env python3
"""Download CIC-IDS2017 Network-Flows from HuggingFace."""

import os

# Force all temp/cache files onto the 1TB SSD, not root filesystem
os.environ["TMPDIR"] = "/mnt/ai_memory/tmp"
os.environ["HF_HOME"] = "/mnt/ai_memory/hf_home"

from huggingface_hub import login, hf_hub_download
import pandas as pd

TOKEN_PATH = "/mnt/ai_memory/main/token.txt"
DATA_DIR = "/mnt/ai_memory/datasets"
OUTPUT_FILE = os.path.join(DATA_DIR, "cic_ids2017_flows.parquet")


def download():
    if os.path.exists(OUTPUT_FILE):
        df = pd.read_parquet(OUTPUT_FILE)
        print(f"[skip] Already downloaded: {OUTPUT_FILE} ({len(df):,} rows)")
        return

    # Authenticate with HuggingFace token
    if os.path.exists(TOKEN_PATH):
        token = open(TOKEN_PATH).read().strip()
        login(token=token, add_to_git_credential=False)
        print("[auth] Logged in with HuggingFace token")
    else:
        print("[auth] No token found, using anonymous access")

    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs("/mnt/ai_memory/tmp", exist_ok=True)

    # Download only the Network-Flows parquet file (~353MB)
    print("[download] Fetching Network-Flows/CICIDS_Flow.parquet...")
    local_path = hf_hub_download(
        "rdpahalavan/CIC-IDS2017",
        "Network-Flows/CICIDS_Flow.parquet",
        repo_type="dataset",
        cache_dir=os.path.join(DATA_DIR, "hf_cache"),
    )

    # Read and keep only needed columns
    print("[process] Reading and filtering columns...")
    df = pd.read_parquet(local_path)
    print(f"  Total rows: {len(df):,}, columns: {len(df.columns)}")

    df.to_parquet(OUTPUT_FILE, index=False)

    # Clean up the HF cache
    import shutil
    cache_path = os.path.join(DATA_DIR, "hf_cache")
    if os.path.exists(cache_path):
        shutil.rmtree(cache_path)

    size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    print(f"[done] Saved {len(df):,} rows to {OUTPUT_FILE} ({size_mb:.0f} MB)")


if __name__ == "__main__":
    download()
