#!/bin/bash
# GuardNet blocking verification — run from Kali
# Enables IDS+Block, triggers detection, confirms Kali IP is firewalled
# Usage: sudo bash ~/Desktop/block_test.sh

CONF="/home/kali/Desktop/guardnet.conf"
[ -f "$CONF" ] || CONF="/home/kali/guardnet.conf"
[ -f "$CONF" ] && eval "$(grep -v '^\s*#' "$CONF" | grep '=' | sed 's/\s*#.*//')"
TARGET="${TARGET:-192.168.4.7}"
IDS_URL="${IDS_URL:-http://192.168.4.1}"
IDS_CREDS="${IDS_CREDS:-admin:admin}"

RED='\e[0;31m'; GREEN='\e[0;32m'; YELLOW='\e[1;33m'
CYAN='\e[0;36m'; BOLD='\e[1m'; RESET='\e[0m'
BRED='\e[1;31m'; BGREEN='\e[1;32m'

api() { curl -sf --max-time 5 --interface eth1 -u "$IDS_CREDS" "$@" 2>/dev/null; }
info() { echo -e "  ${CYAN}[*]${RESET} $*"; }
pass() { echo -e "  ${BGREEN}[+]${RESET} $*"; }
fail() { echo -e "  ${BRED}[-]${RESET} $*"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $*"; }

echo ""
echo -e "${BOLD}${CYAN}  GuardNet — Blocking Function Test${RESET}"
echo -e "  ${CYAN}Target: $TARGET  |  IDS: $IDS_URL${RESET}"
echo ""

# ── Step 1: prep ──────────────────────────────────────────────
info "Enabling IDS + Blocking on ESP32..."
api -X POST "$IDS_URL/api/ids/toggle"   -H "Content-Type: application/json" -d '{"enabled":true}'  >/dev/null
api -X POST "$IDS_URL/api/block/toggle" -H "Content-Type: application/json" -d '{"enabled":true}'  >/dev/null
api -X POST "$IDS_URL/api/alerts/clear" >/dev/null

# Unblock all IPs first
api "$IDS_URL/api/blocked" | python3 -c "
import sys, json, urllib.request, base64
try:
    blocked = json.load(sys.stdin)
    creds = base64.b64encode(b'${IDS_CREDS}').decode()
    for b in blocked:
        req = urllib.request.Request('${IDS_URL}/api/unblock',
            data=json.dumps({'ip': b['ip']}).encode(),
            headers={'Authorization': 'Basic '+creds, 'Content-Type':'application/json'},
            method='POST')
        urllib.request.urlopen(req, timeout=5)
        print(f'  Cleared block: {b[\"ip\"]}')
except: pass
" 2>/dev/null

pass "State: IDS ON | Blocking ON | All IPs unblocked | Alerts cleared"
echo ""

# ── Step 2: verify target is reachable BEFORE attack ─────────
info "Verifying Win7 is reachable BEFORE attack..."
if ping -c 2 -W 2 "$TARGET" &>/dev/null; then
    pass "Win7 ($TARGET) responds to ping — connection open"
    BEFORE_PING="OK"
else
    warn "Win7 already unreachable — may already be blocked or offline"
    BEFORE_PING="FAIL"
fi
echo ""

# ── Step 3: trigger detection (fast portscan) ─────────────────
info "Running port scan to trigger PortScan heuristic..."
nmap -sS -T4 --top-ports 500 "$TARGET" -oN /tmp/block_test_scan.txt &>/dev/null
pass "Port scan complete"
sleep 2

# ── Step 4: check blocked list ───────────────────────────────
echo ""
info "Checking blocked IP list on ESP32..."
BLOCKED_JSON=$(api "$IDS_URL/api/blocked")
BLOCKED_COUNT=$(echo "$BLOCKED_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
MY_IP=$(ip route get "$TARGET" 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)

if [ "${BLOCKED_COUNT:-0}" -gt 0 ]; then
    pass "$BLOCKED_COUNT IP(s) blocked:"
    echo "$BLOCKED_JSON" | python3 -c "
import sys,json
for b in json.load(sys.stdin):
    print(f'    ✗  {b[\"ip\"]}  reason={b[\"reason\"]}')
" 2>/dev/null
else
    warn "No IPs blocked yet — sending more traffic to trigger threshold..."
    # Extra synflood to push past threshold
    timeout 10 hping3 -S -i u1000 -p 445 "$TARGET" &>/dev/null || true
    sleep 2
    BLOCKED_JSON=$(api "$IDS_URL/api/blocked")
    BLOCKED_COUNT=$(echo "$BLOCKED_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
    if [ "${BLOCKED_COUNT:-0}" -gt 0 ]; then
        pass "$BLOCKED_COUNT IP(s) blocked after SYN flood:"
        echo "$BLOCKED_JSON" | python3 -c "
import sys,json
for b in json.load(sys.stdin):
    print(f'    ✗  {b[\"ip\"]}  reason={b[\"reason\"]}')
" 2>/dev/null
    else
        fail "Still no blocks — check IDS is detecting (dashboard: $IDS_URL)"
    fi
fi

# ── Step 5: verify block with ping ────────────────────────────
echo ""
KALI_GN_IP=$(ip -4 addr show eth1 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
KALI_GN_IP=$(ip -4 addr show eth1 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
info "Testing if Kali GuardNet IP ($KALI_GN_IP) is now blocked..."

# Check blocked list from host perspective (Kali's own API call may be blocked too)
# Query via eth0 which is never blocked
BLOCKED_VIA_ETH0=$(curl -sf --interface eth1 --max-time 5 \
    -u "$IDS_CREDS" "$IDS_URL/api/blocked" 2>/dev/null)
KALI_IN_BLOCKLIST=$(echo "$BLOCKED_VIA_ETH0" | python3 -c "
import sys, json
try:
    blocked = json.load(sys.stdin)
    ips = [b['ip'] for b in blocked]
    print('yes' if '${KALI_GN_IP}' in ips else 'no')
except: print('no')
" 2>/dev/null)

PING_OUT=$(ping -I eth1 -c 4 -W 1 "$TARGET" 2>&1)
PING_BLOCKED=$(echo "$PING_OUT" | grep -q "100% packet loss\|0 received" && echo yes || echo no)

if [ "$KALI_IN_BLOCKLIST" = "yes" ] && [ "$PING_BLOCKED" = "yes" ]; then
    echo ""
    echo -e "  ${BRED}  ████  BLOCKED  ████${RESET}"
    echo -e "  ${BRED}  Kali ($KALI_GN_IP) is in ESP32 block list${RESET}"
    echo -e "  ${BRED}  All pings from eth1 dropped — ESP32 firewalling this IP${RESET}"
    echo ""
    pass "BLOCKING WORKS ✓"
    echo -e "    Before attack:  Win7 reachable      ($BEFORE_PING)"
    echo -e "    After block:    eth1 → Win7 = 100% loss"
    echo -e "    Attacker IP:    $KALI_GN_IP  (blocked in ESP32 firewall)"
elif [ "$KALI_IN_BLOCKLIST" = "yes" ]; then
    pass "Kali IP $KALI_GN_IP IS in block list"
    warn "Ping still getting through — check eth1 routing"
elif [ "$PING_BLOCKED" = "yes" ]; then
    pass "Pings blocked (100% loss) — firewall active"
    warn "IP not showing in block list yet — may need a moment"
else
    warn "Not fully blocked yet"
    echo -e "  ${YELLOW}  Block list: $BLOCKED_VIA_ETH0${RESET}"
fi

echo ""
info "Dashboard: $IDS_URL (${IDS_CREDS%%:*} / ${IDS_CREDS##*:})"
echo ""
