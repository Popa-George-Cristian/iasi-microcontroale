# GuardNet — Project Overview

ESP32-S3 TinyML Network Intrusion Detection System. Acts as a WiFi access point with NAT, inspects all traffic using a neural network, and blocks malicious IPs in real time. Built for a competition in Iași.

---

## How It Works — End to End

```
Internet
   │
[Home Router]
   │
[ESP32-S3 GuardNet]  ←── STA uplink (connects to home router as a client)
   │  AP: 192.168.4.1
   │
   ├── Your laptop      192.168.4.4
   ├── Kali VM          192.168.4.5  (attacker in demo)
   └── Windows 7 VM     192.168.4.35 (target in demo)
```

All traffic from clients flows through the ESP32. Every packet is inspected before being forwarded.

---

## The Three Layers of Defense

### Layer 1 — Packet Hook (main.c)
A lwIP netif input hook intercepts every Ethernet frame arriving at the AP interface. For each IP packet it:
1. Checks if the source IP is already blocked → drops packet immediately if so
2. Extracts TCP/UDP ports and flags
3. Updates the **flow table** (bidirectional 5-tuple tracking)
4. Updates the **IP tracker** for heuristic detection
5. Runs ML inference every 5 packets per flow

### Layer 2 — Heuristic Detectors (main.c)
Two fast rule-based detectors that catch attacks without waiting for ML:

| Detector | Threshold | Category |
|----------|-----------|----------|
| Port Scan | 120+ new SYN-initiated flows in 10s | PortScan |
| SYN Flood | 200+ pure SYNs (not SYN-ACK) in 10s | DoS |

Key design decisions (all validated with tests):
- Only **pure SYN** packets (flag `0x02` without `0x10`) count toward thresholds — SYN-ACK responses from the victim are excluded so the victim is never misidentified as an attacker.
- Only flows **initiated with a SYN** increment the scanner counter — RST/ACK-first packets (victim responses landing in a new flow slot after table overflow) are excluded.
- Attack is always attributed to **`flow->src_ip`** (the connection initiator), never to the responder. This applies to both heuristics and the ML trigger.
- Internal AP clients are blocked the same as external attackers — the `!internal` restriction was removed since the demo attacker (Kali) is on the AP subnet.

### Layer 3 — TinyML Model (ids_engine.c)
INT8 quantized 3-layer neural network: **30→128→64→8**
- Input: 30 flow-level features (packet rates, IAT stats, TCP flags, window sizes)
- Output: 8 categories — Normal, DoS, DDoS, PortScan, BruteForce, WebAttack, Infiltration, Botnet
- Trained on CIC-IDS2017 dataset, knowledge-distilled from a larger teacher model
- ~13K parameters, ~1.5ms inference on ESP32-S3
- ~3.5x smaller and ~5-10x faster than float32 via INT8 SIMD

The model fires every 5 packets on a flow. If confidence > threshold (default 0.85), an alert is logged and — if blocking is enabled — the attacker IP is firewalled.

---

## Flow of an Attack Detection

```
Kali (192.168.4.5) → SYN flood → Win7 (192.168.4.35)
        │
        ▼
ESP32 AP netif hook receives each packet
        │
        ├─ firewall_is_blocked(192.168.4.5)? → NO (first time)
        │
        ├─ find_or_create_flow(192.168.4.5, 192.168.4.35, ...)
        │
        ├─ ip_tracker[192.168.4.5].syn_count++
        │   (200th pure SYN in 10s)
        │
        ├─ check_heuristics() → SYNFLOOD threshold hit
        │       → firewall_log_alert(src=192.168.4.5, dst=192.168.4.35, DoS)
        │       → firewall_block_ip(192.168.4.5)
        │
        ▼
All future packets from 192.168.4.5 dropped at line 1
Win7 is safe. Dashboard shows the alert.
```

---

## Key Files

| File | What it does |
|------|-------------|
| `firmware/main/main.c` | Packet hook, flow table, heuristics, ML trigger |
| `firmware/main/ids_engine.c` | INT8 NN inference, MinMax scaling, INT8 quantization |
| `firmware/main/firewall.c` | Block list (mutex-protected), alert ring buffer |
| `firmware/main/wifi_manager.c` | AP+STA concurrent mode, NAPT forwarding |
| `firmware/main/web_server.c` | HTTP REST API + embedded dashboard |
| `firmware/main/model_data.h` | Auto-generated INT8 weights from training pipeline |
| `firmware/main/frontend/` | Dashboard HTML/CSS/JS, embedded at build time |
| `training/train_model.py` | PyTorch training, knowledge distillation, INT8 export |
| `tools/demo.sh` | Jury demonstration script (4 phases) |
| `tools/attack_test.sh` | Full attack suite (all 7 categories) |
| `tools/block_test.sh` | Quick blocking verification |
| `tools/eternalblue_drop.sh` | EternalBlue MS17-010 file drop on Win7 |

---

## Dashboard API

Base URL: `http://192.168.4.1`  Credentials: `admin:admin`

All API calls use HTTP Basic Auth. From terminal:
```bash
curl -u admin:admin http://192.168.4.1/api/status
curl -u admin:admin -X POST http://192.168.4.1/api/ids/toggle \
     -H "Content-Type: application/json" -d '{"enabled":true}'
```

| Endpoint | Method | Body | Description |
|----------|--------|------|-------------|
| `/api/status` | GET | — | Uptime, clients, attack count, IDS/block/threshold/inference/timeout |
| `/api/alerts` | GET | — | Alert log (last 50) — src/dst/category/confidence/features array |
| `/api/blocked` | GET | — | Blocked IPs with reason, timestamp, `remaining` seconds |
| `/api/clients` | GET | — | Connected AP clients (MAC, IP, RSSI, bridged flag) |
| `/api/timeline` | GET | — | 10 integers — attacks per minute, oldest→newest (10-min window) |
| `/api/ids/toggle` | POST | `{"enabled":bool}` | Enable/disable the TinyML IDS |
| `/api/block/toggle` | POST | `{"enabled":bool}` | Enable/disable IP blocking (monitor-only when false) |
| `/api/block/timeout` | POST | `{"minutes":5}` | Set auto-unblock timer (0 = permanent) |
| `/api/block` | POST | `{"ip":"x.x.x.x"}` | Manually block an IP |
| `/api/unblock` | POST | `{"ip":"x.x.x.x"}` | Unblock a specific IP |
| `/api/alerts/clear` | POST | — | Clear alert log and reset attack counter (timeline unaffected) |
| `/api/confidence` | POST | `{"threshold":0.85}` | Set ML confidence threshold (persists via NVS) |
| `/api/disconnect` | POST | `{"mac":"xx:xx:xx:xx:xx:xx"}` | Deauth a WiFi client by MAC |
| `/api/wifi/status` | GET | — | Upstream WiFi SSID and connection state |
| `/api/wifi/scan` | GET | — | Scan nearby WiFi networks |
| `/api/wifi/connect` | POST | `{"ssid":"...","pass":"..."}` | Save upstream WiFi credentials |
| `/api/wifi/forget` | POST | — | Clear upstream WiFi credentials |
| `/api/auth/check` | GET | — | Verify credentials (used by dashboard login) |
| `/api/auth/change` | POST | `{"old":"...","new":"..."}` | Change dashboard password |

### Useful one-liners

```bash
BASE="http://192.168.4.1"; AUTH="-u admin:admin"

# Full status
curl -s $AUTH $BASE/api/status | python3 -m json.tool

# Live attack feed (poll every 2s)
watch -n2 'curl -s -u admin:admin http://192.168.4.1/api/alerts | python3 -c "
import sys,json
for a in json.load(sys.stdin):
    print(a[\"cat\"], a[\"src\"], \"→\", a[\"dst\"], int(a[\"conf\"]*100), \"%\")
"'

# Enable IDS + blocking
curl -s $AUTH -X POST $BASE/api/ids/toggle   -H "Content-Type: application/json" -d '{"enabled":true}'
curl -s $AUTH -X POST $BASE/api/block/toggle -H "Content-Type: application/json" -d '{"enabled":true}'

# Set 5-minute auto-unblock
curl -s $AUTH -X POST $BASE/api/block/timeout -H "Content-Type: application/json" -d '{"minutes":5}'

# Unblock all IPs
curl -s $AUTH $BASE/api/blocked | python3 -c "
import sys,json,subprocess
for b in json.load(sys.stdin):
    subprocess.run(['curl','-sf','-u','admin:admin','-X','POST',
        'http://192.168.4.1/api/unblock','-H','Content-Type: application/json',
        '-d',f'{{\"ip\":\"{b[\"ip\"]}\"}}'])
    print('Unblocked', b['ip'])
"

# Lower confidence threshold for sensitive demo
curl -s $AUTH -X POST $BASE/api/confidence -H "Content-Type: application/json" -d '{"threshold":0.70}'

# Restore default threshold
curl -s $AUTH -X POST $BASE/api/confidence -H "Content-Type: application/json" -d '{"threshold":0.85}'

# Timeline (attacks per minute, last 10 min)
curl -s $AUTH $BASE/api/timeline

# Serial monitor (ESP32 must be USB-connected)
cat /dev/ttyACM0   # or: idf.py monitor
```

---

## Demo Script Flow (tools/demo.sh)

Run from Kali: `sudo bash ~/Desktop/demo.sh`

Each phase pauses and shows a `SHOW JURY` callout with talking points.

| Phase | IDS | Block | What the jury sees |
|-------|-----|-------|-------------------|
| 1 | OFF | OFF | Port scan + SYN flood invisible. **EternalBlue fires → GUARDNET_OWNED.txt appears on Win7 Desktop.** Dashboard shows 0 attacks. |
| 2 | ON | OFF | Same attacks. Live detection feed prints each attack as it's classified. Dashboard shows categories + confidence bars. |
| 3 | ON | ON | Kali IP blocked after portscan. TCP connect from Kali to Win7 fails. Blocked IPs panel shows countdown timer. |
| 4 | ON | ON | **EternalBlue fired again — IDS blocks Kali before SMB reaches Win7. GUARDNET_BLOCKED_ATTEMPT.txt is NOT on the desktop.** |

**The killer comparison for the jury:** Win7 Desktop has `OWNED.txt` (Phase 1 — no defense) but NOT `BLOCKED_ATTEMPT.txt` (Phase 4 — GuardNet stopped it). Same exploit, same target, one difference.

**EternalBlue implementation:** Uses `windows/x64/exec` payload (fire-and-forget, no reverse shell). Win7 is confirmed vulnerable to MS17-010 (CVE-2017-0144). The exec payload writes directly to `C:\Users\Public\Desktop\` without needing a callback connection — routing-agnostic.

---

## Attack Categories vs Detection Method

| Category | How GuardNet detects it |
|----------|------------------------|
| PortScan | Heuristic: 120+ new SYN flows in 10s |
| DoS | Heuristic: 200+ SYNs in 10s; ML: Hulk/GoldenEye/Slowloris flow features |
| DDoS | ML: high packet rate, short IAT, LOIC-style UDP/TCP floods |
| BruteForce | ML: many flows to same dst_port (SSH-Patator pattern) |
| WebAttack | ML: HTTP traffic with SQL/XSS payload size patterns |
| Infiltration | ML: MS17-010 SMB traffic, low-and-slow post-exploit patterns |
| Botnet | ML: periodic small flows, consistent IAT (ARES C2 pattern) |

---

## Network Setup for Demo

```
Kali VM:
  eth0  10.0.2.15     VirtualBox NAT (SSH tunnel on host:2222)  — never blocked
  eth1  192.168.4.5   Bridged to wlp4s0 → GuardNet AP (static) — gets blocked

Host laptop:
  wlp4s0  192.168.4.4   Connected to GuardNet AP

Windows 7 VM:
  eth0  192.168.4.35  Bridged to wlp4s0 → GuardNet AP

ESP32-S3 GuardNet:
  AP  192.168.4.1   Gateway for all lab devices
  STA 192.168.4.x   Connected to home router for internet
```

**Critical:** Kali's eth1 must have 192.168.4.5 set **statically** — VirtualBox bridged adapters sometimes get DHCP from the wrong server (home router at 172.16.91.x instead of GuardNet at 192.168.4.x):
```bash
sudo nmcli con mod 'Wired connection 2' ipv4.method manual ipv4.addresses '192.168.4.5/24' ipv4.gateway ''
sudo nmcli con up 'Wired connection 2'
```

**Why two adapters on Kali:** eth0 (NAT) is used for SSH access from the host. When Kali's eth1 gets blocked by GuardNet, eth0 is unaffected — the demo script can keep running and querying the dashboard via eth0 (`api_safe()` in demo.sh forces eth0 for all status queries).

**Known IPs:**
- `192.168.4.1` — ESP32 GuardNet AP gateway / dashboard
- `192.168.4.2` — unknown device (phone/laptop on GuardNet, ignore)
- `192.168.4.4` — host laptop (wlp4s0)
- `192.168.4.5` — Kali VM eth1 (attacker)
- `192.168.4.35` — Windows 7 VM (target, IP changes on reboot — update guardnet.conf)

---

## Building and Flashing

```bash
# Requires ESP-IDF v5.4+ with $IDF_PATH set
. ~/esp/esp-idf/export.sh
cd firmware
idf.py build
idf.py -p /dev/ttyACM0 flash
```

Training pipeline (Python/PyTorch, run on machine with GPU):
```bash
cd training
pip install -r requirements.txt
python download_dataset.py   # downloads CIC-IDS2017 via kagglehub
python train_model.py        # trains, exports model_data.h to firmware/main/
```

---

## Known Constraints

- 30 features in `SELECTED_FEATURES` (train_model.py), `flow_features_t` struct (ids_engine.h), and `build_features()` (main.c) must stay in sync — retraining needed after any change.
- Max 128 simultaneous tracked flows. Under heavy scanning the table fills up; oldest flow is evicted.
- Block list capped at 64 IPs, alert log at 50 entries (ring buffer, oldest overwritten).
- Confidence threshold adjustable at runtime via dashboard (default 0.85). Lower = more sensitive but more false positives.
- Alerts and block list are lost on reboot — only the confidence threshold and dashboard password persist via NVS.
- Windows 7 VM IP changes on reboot — update `TARGET` in `/home/kali/guardnet.conf` after each Win7 reboot.

## Potential Improvements

| Priority | Feature | Notes |
|----------|---------|-------|
| High | **WiFi deauth on block** | Kick attacker off AP entirely, not just drop packets. Needs AID lookup via `esp_wifi_ap_get_sta_list`. Most visually dramatic for demo. |
| High | **Auto-unblock timer** | Blocked IPs unblock after N min. Prevents lockouts during demo. Add `unblock_at` timestamp to `blocked_entry_t`. |
| High | **Live attack timeline chart** | Canvas bar chart, attacks/min over 10min. Add `/api/timeline` endpoint with 60-bucket counter in firewall.c. |
| Medium | **Alert persistence (NVS)** | Store last 20 alerts across reboots. |
| Medium | **Feature drill-down** | Click alert row → expand to show all 30 ML features. Data already in alert JSON. |
| Low | **Page title badge** | `document.title = \`(N) GuardNet\`` — zero firmware change. |
| Low | **Block reason badge colors** | Color blocked IPs by category in dashboard. |
