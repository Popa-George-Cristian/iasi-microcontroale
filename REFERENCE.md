# GuardNet — Commands & Settings Reference

Quick reference for day-to-day use: build, flash, monitor, and where every
tunable lives.

## 1. Environment Setup

Run this once per shell before any `idf.py` command:

```bash
. /home/cristi/esp/esp-idf/export.sh
```

Python env for training (separate from IDF):

```bash
source /mnt/ai_memory/aienv/bin/activate
```

## 2. Firmware — Build / Flash / Monitor

All from `/home/cristi/iasiproiect/firmware`.

| Goal | Command |
|------|---------|
| Fresh build | `idf.py build` |
| Flash (USB on /dev/ttyACM0) | `idf.py -p /dev/ttyACM0 flash` |
| Flash + serial monitor | `idf.py -p /dev/ttyACM0 flash monitor` |
| Serial monitor only | `idf.py -p /dev/ttyACM0 monitor` (Ctrl+] to exit) |
| Wipe build dir | `idf.py fullclean` |
| Erase all NVS on device | `idf.py -p /dev/ttyACM0 erase-flash` |
| Interactive sdkconfig | `idf.py menuconfig` |
| Check target | `cat sdkconfig | grep IDF_TARGET` (should be `esp32s3`) |

If port is busy: `sudo fuser -k /dev/ttyACM0` or close any open `idf.py monitor`.

## 3. Training Pipeline

From `/home/cristi/iasiproiect/training`.

```bash
pip install -r requirements.txt      # first time only
python download_dataset.py           # pulls CIC-IDS2017 via kagglehub
python train_model.py                # trains + writes model_data.h
```

Outputs:
- `training/output/guardnet_model.pt` — PyTorch checkpoint
- `training/output/model_data.h` — generated weights
- `firmware/main/model_data.h` — same file, copied into firmware tree
- `training/output/confusion_matrix.png` — eval plot

After retraining: rebuild firmware (`idf.py build`) to pick up new weights.

## 4. Dashboard

| Item | Value |
|------|-------|
| URL (mDNS) | http://esp-firewall.local/ |
| URL (AP-side IP) | http://192.168.4.1/ |
| Default dashboard user | `admin` |
| Default dashboard password | `admin` (change via Settings panel) |
| AP SSID | `GuardNet` |
| AP password | `guardnet123` |

Connect your laptop/phone to the `GuardNet` AP, then load the dashboard.

## 5. Runtime Settings (Web UI)

Changeable from the dashboard without reflashing. All persist to NVS.

| Setting | Where in UI | API endpoint |
|---------|-------------|--------------|
| IDS on/off | Header button "IDS: ON/OFF" | `POST /api/ids/toggle` `{"enabled":bool}` |
| Block on/off (monitor-only if off) | Header button "Block: ON/OFF" | `POST /api/block/toggle` `{"enabled":bool}` |
| Paranoia level (confidence threshold) | Settings → Paranoia slider | `POST /api/confidence` `{"threshold":0.50..0.95}` |
| Dashboard password | Settings → Change Password | `POST /api/auth/change` `{"old":"..","new":".."}` |
| Upstream WiFi | WiFi Configuration panel | `POST /api/wifi/connect` |
| Forget upstream WiFi | WiFi Configuration → Forget | `POST /api/wifi/forget` |
| Manual block an IP | Blocked IPs → input + Block | `POST /api/block` `{"ip":"1.2.3.4"}` |
| Unblock an IP | Blocked IPs → Unblock button | `POST /api/unblock` `{"ip":"1.2.3.4"}` |
| Disconnect a client | Connected Clients → Disconnect | `POST /api/disconnect` `{"mac":"aa:bb:.."}` |

Read-only endpoints: `/api/status`, `/api/alerts`, `/api/blocked`,
`/api/clients`, `/api/wifi/status`, `/api/wifi/scan`.

### Paranoia slider semantics

Slider maps 50 → 95 to confidence threshold 0.50 → 0.95.

- **Low threshold (Tinfoil end)** = IDS fires on weaker signals → more attacks
  caught, more false positives.
- **High threshold (Chill end)** = IDS only fires when very sure → fewer false
  alarms, may miss stealthy attacks.
- Default: 0.80.
- Stored in NVS namespace `guardnet`, key `conf_thresh` (blob of 1 float).

## 6. Compile-Time Settings (edit + reflash)

### Upstream WiFi fallback credentials

Only used if nothing saved in NVS. Normally leave blank and set via dashboard.

- File: `firmware/main/main.c` — grep `STA_SSID` / `STA_PASS` if hardcoded.

### AP configuration

File: `firmware/main/wifi_manager.h`

```c
#define GUARDNET_AP_SSID     "GuardNet"
#define GUARDNET_AP_PASS     "guardnet123"
#define GUARDNET_AP_CHANNEL  1
#define GUARDNET_AP_MAX_CONN 8
```

### IDS core tunables

File: `firmware/main/main.c`

| Macro | Default | Purpose |
|-------|---------|---------|
| `MAX_FLOWS` | 128 | Flow table size |
| `FLOW_TIMEOUT_US` | 120 s | Flow eviction timeout |
| `INSPECT_EVERY_N_PKTS` | 5 | Run NN every N packets per flow |
| `CLASSIFY_MIN_PKTS` | 3 | Min packets before classifying on eviction |
| `CONFIDENCE_THRESHOLD` | `s_conf_threshold` | **Runtime** via slider (default 0.80) |
| `CONF_DEFAULT` / `CONF_MIN` / `CONF_MAX` | 0.80 / 0.50 / 0.95 | Slider bounds / default |
| `MAX_IP_TRACKERS` | 32 | Per-IP heuristic trackers |
| `TRACKER_WINDOW_US` | 10 s | Sliding window for scan/flood detection |
| `PORTSCAN_THRESHOLD` | 25 | New flows / 10s that trigger scan alert |
| `SYNFLOOD_THRESHOLD` | 60 | SYNs / 10s that trigger flood alert |
| `MAX_SEEN_CLIENTS` | 16 | Clients discovered via packet inspection |
| `AP_SUBNET` | 192.168.4.0/24 | Internal subnet mask for is_ap_client |

### Dashboard auth defaults

File: `firmware/main/web_server.c`

```c
#define DEFAULT_PASS       "admin"
#define MAX_PASS_LEN       32
#define NVS_AUTH_NAMESPACE "guardnet"
#define NVS_AUTH_KEY       "dash_pass"
```

### Hardware / SDK config

File: `firmware/sdkconfig.defaults` — PSRAM, NAPT, 16 MB flash target.
Edit + `idf.py fullclean && idf.py build` to apply.

Target is pinned to `esp32s3` in `firmware/dependencies.lock`.

## 7. NVS Layout (on-device persistent state)

Namespace `guardnet`:

| Key | Type | Meaning |
|-----|------|---------|
| `dash_pass` | string | Dashboard admin password |
| `conf_thresh` | blob(float) | Paranoia / confidence threshold |
| (wifi_manager writes additional keys for STA creds) | | |

Wipe everything with `idf.py -p /dev/ttyACM0 erase-flash` then reflash — this
resets the dashboard password, paranoia slider, and saved upstream WiFi.

## 8. Model / Feature Sync

The 30 features must stay in sync across three places. Change one → change all
three and retrain:

1. `SELECTED_FEATURES` in `training/train_model.py`
2. `flow_features_t` struct in `firmware/main/ids_engine.h`
3. `build_features()` in `firmware/main/main.c`

## 9. Kali Attack VM

SSH to attack box (used for IDS testing):

```bash
ssh -i ~/.ssh/kali_vm -p 2222 kali@localhost
```

## 10. Confidence Threshold — Calibration Results

Empirically tested 2026-04-22 with Kali VM generating realistic normal traffic
(30 HTTP requests + 40 pings through ESP32 NAT).

| Threshold | Normal traffic result | Notes |
|-----------|----------------------|-------|
| 0.95 | ✅ 0 false positives | Very conservative |
| 0.90 | ✅ 0 false positives | |
| 0.85 | ✅ 0 false positives | |
| **0.80** | ✅ **0 false positives** | **← recommended default** |
| 0.75 | ✅ 0 false positives | Marginal (reboot mid-test) |
| 0.70 | ❌ 1 false positive | Normal traffic flagged |

**Why confidence is almost always >90% for real attacks**: the softmax output is
sharp when the model sees clear feature signatures (DoS flood, port scan). This
is expected — the model was trained on CIC-IDS2017 which has clean, well-separated
attack patterns. label_smoothing=0.1 during training prevents it getting *worse*.

**Why class weights can cause false positives at low threshold**: training uses
inverse-frequency weighting — rare attack classes get 50x higher loss weight than
Normal. The model optimizes recall (catch rare attacks) over precision (avoid FP).
Lower threshold undoes this by accepting weaker evidence.

## 11. Known Bugs Fixed (2026-04-22)

| Bug | Root cause | Fix |
|-----|-----------|-----|
| 127.x.x.x PORTSCAN/SYN FLOOD every 10s | ESP32 own HTTP/loopback traffic leaked into AP netif packet hook | Early exit in `inspect_packet` for 127.x.x.x, self IP, broadcast |
| Client kicked off AP every ~20 min | `pmf_cfg` not set → driver defaulted to PMF capable → SA Query kick loop under load | `pmf_cfg.required=false, capable=false` in `wifi_manager_init` |
| Block mode deauths ALL clients not just attacker | `esp_wifi_deauth_sta(0)` — AID=0 = broadcast deauth | Replaced with `firewall_block_ip` — drops at packet hook, no WiFi kick |

All three confirmed fixed: 30 HTTP + 40 pings with no false positives and no
SA Query disconnects.

## 13. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard unreachable | Check AP SSID `GuardNet` visible; mDNS sometimes flaky — use `http://192.168.4.1/` |
| Clients can't reach internet | Upstream WiFi not connected; reconfigure in WiFi Configuration panel |
| Forgot dashboard password | `idf.py -p /dev/ttyACM0 erase-flash` (wipes NVS) + reflash |
| Too many false positives | Slide Paranoia toward "Chill" (higher threshold) |
| Missing attacks | Slide Paranoia toward "Tinfoil" (lower threshold) |
| Serial port busy | `sudo fuser -k /dev/ttyACM0` |
| "A fatal error occurred: Failed to connect" during flash | Hold BOOT, tap RESET, release BOOT, retry flash |
