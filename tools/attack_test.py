#!/usr/bin/env python3
"""
GuardNet IDS — automated attack test and threshold calibration.
Runs attacks from Kali VM against Windows target through ESP32, measures detection.

Usage:
    python attack_test.py [--target 192.168.4.3] [--esp32 192.168.4.1]
"""
import subprocess, time, json, sys, argparse, requests
from requests.auth import HTTPBasicAuth

KALI_SSH   = ["ssh", "-i", "/home/cristi/.ssh/kali_vm", "-p", "2222",
               "-o", "StrictHostKeyChecking=no", "kali@127.0.0.1"]
ESP32_URL  = "http://192.168.4.1"
AUTH       = HTTPBasicAuth("admin", "admin")
STEP       = 0.05   # threshold adjustment step
THRESHOLD_MIN = 0.70
THRESHOLD_MAX = 0.95

def esp_status():
    try:
        r = requests.get(f"{ESP32_URL}/api/status", auth=AUTH, timeout=5)
        return r.json()
    except Exception:
        return None

def esp_alerts():
    try:
        r = requests.get(f"{ESP32_URL}/api/alerts", auth=AUTH, timeout=5)
        return r.json()
    except Exception:
        return []

def set_threshold(t):
    t = round(max(THRESHOLD_MIN, min(THRESHOLD_MAX, t)), 2)
    try:
        r = requests.post(f"{ESP32_URL}/api/confidence",
                          json={"threshold": t}, auth=AUTH, timeout=5)
        d = r.json()
        return d.get("conf_threshold", t)
    except Exception:
        return t

def kali(cmd, timeout=30):
    result = subprocess.run(KALI_SSH + ["bash", "-c", cmd],
                            capture_output=True, text=True, timeout=timeout+5)
    return result.returncode, result.stdout.strip()

def kali_setup(target):
    kali("sudo ip addr add 192.168.4.5/24 dev eth1 2>/dev/null; "
         "sudo ip route add 192.168.4.0/24 dev eth1 2>/dev/null")
    rc, out = kali(f"ping -c 2 -W 2 -I eth1 {target} 2>&1 | tail -1")
    return "0% packet loss" in out

def count_new_alerts(before_count, cat=None):
    alerts = esp_alerts()
    if cat:
        new = [a for a in alerts if a["cat"] == cat]
    else:
        new = alerts
    return max(0, len(new) - before_count)

def run_test(name, attack_cmd, expected_cat, target, timeout=20):
    print(f"\n  [{name}]", end=" ", flush=True)
    s = esp_status()
    if not s:
        print("ESP32 unreachable"); return None
    before = s["total_attacks"]

    kali(attack_cmd, timeout=timeout+5)
    time.sleep(3)

    s2 = esp_status()
    new_attacks = (s2["total_attacks"] - before) if s2 else 0

    if new_attacks > 0:
        alerts = esp_alerts()
        detected = [a for a in alerts if a["cat"] == expected_cat]
        if detected:
            conf = max(a["conf"] for a in detected[-3:])
            print(f"DETECTED ✓  conf={conf*100:.0f}%  [{expected_cat}]")
            return ("detected", conf)
        else:
            cats = list({a["cat"] for a in alerts[-new_attacks:]})
            print(f"WRONG CAT ≈  got={cats}  expected={expected_cat}")
            return ("wrong_cat", 0)
    else:
        print(f"MISSED ✗  [{expected_cat}]")
        return ("missed", 0)

def run_normal(duration=15):
    print(f"\n  [Normal traffic {duration}s]", end=" ", flush=True)
    s = esp_status()
    before = s["total_attacks"] if s else 0
    kali(f"for i in $(seq 1 {duration//2}); do "
         f"curl -s --max-time 2 --interface eth1 http://192.168.4.1/ -o /dev/null; sleep 2; done", timeout=duration+5)
    time.sleep(2)
    s2 = esp_status()
    new = (s2["total_attacks"] - before) if s2 else 0
    if new == 0:
        print("CLEAN ✓")
        return 0
    else:
        print(f"FALSE POSITIVE ✗  +{new} alerts")
        return new

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="192.168.4.3")
    parser.add_argument("--esp32", default="192.168.4.1")
    args = parser.parse_args()
    target = args.target

    print("GuardNet IDS — Attack Calibration Test")
    print("=" * 50)

    s = esp_status()
    if not s:
        print("ERROR: ESP32 not reachable at", ESP32_URL); sys.exit(1)
    threshold = s["conf_threshold"]
    print(f"ESP32 UP  threshold={threshold}  attacks={s['total_attacks']}")

    if not kali_setup(target):
        print(f"WARNING: Kali cannot reach target {target} — tests may fail")

    results = {"detected":0, "missed":0, "fp":0, "total":0}

    for round_num in range(1, 4):
        print(f"\n=== Round {round_num}  threshold={threshold:.2f} ===")

        # Normal traffic — must be clean
        fp = run_normal(duration=20)
        if fp > 0:
            results["fp"] += fp
            new_t = min(THRESHOLD_MAX, threshold + STEP)
            print(f"  → FP detected, raising threshold {threshold:.2f}→{new_t:.2f}")
            threshold = set_threshold(new_t)

        # Attack suite
        attacks = [
            ("SYN Flood",    f"sudo hping3 -S -p 80 --flood -c 500 -I eth1 {target} 2>/dev/null", "DoS"),
            ("Port Scan",    f"sudo nmap -sS -p 1-500 --min-rate 200 -S 192.168.4.5 -e eth1 {target} 2>/dev/null | tail -3", "PortScan"),
            ("UDP Flood",    f"sudo hping3 --udp -p 53 --flood -c 300 -I eth1 {target} 2>/dev/null", "DoS"),
            ("HTTP Brute",   f"hydra -l admin -P /usr/share/wordlists/metasploit/unix_passwords.txt -I -f http-get://{target}/ 2>/dev/null | tail -3", "BruteForce"),
        ]

        for name, cmd, cat in attacks:
            result = run_test(name, cmd, cat, target)
            if result is None: continue
            outcome, conf = result
            results["total"] += 1
            if outcome == "detected":
                results["detected"] += 1
            elif outcome == "missed":
                results["missed"] += 1
                new_t = max(THRESHOLD_MIN, threshold - STEP)
                print(f"  → missed, lowering threshold {threshold:.2f}→{new_t:.2f}")
                threshold = set_threshold(new_t)
            time.sleep(5)

    print(f"\n{'='*50}")
    print(f"RESULTS:")
    print(f"  Detected:        {results['detected']}/{results['total']}")
    print(f"  Missed:          {results['missed']}/{results['total']}")
    print(f"  False positives: {results['fp']}")
    print(f"  Final threshold: {threshold:.2f}")

    dr = results["detected"]/max(results["total"],1)*100
    print(f"  Detection rate:  {dr:.0f}%")
    if results["fp"] == 0 and dr >= 75:
        print(f"\n  ✓ Threshold {threshold:.2f} looks good for demo")
    elif results["fp"] > 0:
        print(f"\n  ⚠ Still FPs — consider raising threshold above {threshold:.2f}")
    else:
        print(f"\n  ⚠ Low detection — consider lowering threshold below {threshold:.2f}")

if __name__ == "__main__":
    main()
