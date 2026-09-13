/*
 * peparse.h - minimal PE64 export/stub parser (HalosGate core)
 * Self-contained (stdint only) so the same code runs in the Windows loader
 * and in the Linux test harness. Structs mirror winnt.h layouts exactly.
 */
#ifndef PEPARSE_H
#define PEPARSE_H

#include <stdint.h>
#include <string.h>

typedef struct {
    uint16_t e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc,
             e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4], e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} MY_DOS;   /* e_lfanew at 0x3C */

typedef struct {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
} MY_FILE_HDR;

typedef struct { uint32_t VirtualAddress; uint32_t Size; } MY_DATADIR;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData,
             AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion, MinorOSVersion, MajorImageVersion, MinorImageVersion,
             MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    MY_DATADIR DataDirectory[16];   /* offset 0x70 for PE32+ */
} MY_OPT64;

typedef struct {
    uint32_t Signature;
    MY_FILE_HDR FileHeader;
    MY_OPT64 OptionalHeader;
} MY_NT64;

typedef struct {
    uint8_t Name[8];
    uint32_t VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;   /* offset 0x24 */
} MY_SEC;

typedef struct {
    uint32_t Characteristics, TimeDateStamp;
    uint16_t MajorVersion, MinorVersion;
    uint32_t Name, Base, NumberOfFunctions, NumberOfNames;
    uint32_t AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} MY_EXP;

#define MY_FIRST_SECTION(nt) ((MY_SEC *)((uint8_t *)(nt) + 4 + 0x14 + (nt)->FileHeader.SizeOfOptionalHeader))

static uint32_t rva_to_off(MY_NT64 *nt, uint32_t rva) {
    MY_SEC *sec = MY_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
    }
    return 0;
}

static uint32_t resolve_ssn(uint8_t *buf, MY_NT64 *nt, const char *zwName) {
    MY_DATADIR *expdd = &nt->OptionalHeader.DataDirectory[0];   /* export dir */
    if (!expdd->VirtualAddress || !expdd->Size) return 0;

    uint32_t expOff = rva_to_off(nt, expdd->VirtualAddress);
    if (!expOff) return 0;
    MY_EXP *exp = (MY_EXP *)(buf + expOff);

    uint32_t *names = (uint32_t *)(buf + rva_to_off(nt, exp->AddressOfNames));
    uint16_t *ords  = (uint16_t *)(buf + rva_to_off(nt, exp->AddressOfNameOrdinals));
    uint32_t *funcs = (uint32_t *)(buf + rva_to_off(nt, exp->AddressOfFunctions));

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        char *n = (char *)(buf + rva_to_off(nt, names[i]));
        if (!strcmp(n, zwName)) {
            uint32_t off = rva_to_off(nt, funcs[ords[i]]);
            if (!off) return 0;
            uint8_t *p = buf + off;

            /* jmp rel32 -> follow (Zw alias thunk to Nt stub) */
            if (p[0] == 0xE9)
                p = p + 5 + *(int32_t *)(p + 1);

            /* mov r10, rcx; mov eax, imm32 */
            if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1) {
                if (p[3] != 0xB8) return 0;
                return *(uint32_t *)(p + 4);
            }
            /* mov eax, imm32 */
            if (p[0] == 0xB8)
                return *(uint32_t *)(p + 1);
            return 0;
        }
    }
    return 0;
}

/* locate code section + first "syscall; ret" (0F 05 C3) gadget */
static int locate_text(uint8_t *buf, MY_NT64 *nt,
                       uint32_t *va, uint32_t *size, uint32_t *off,
                       uintptr_t *gadget, void *liveBase) {
    MY_SEC *sec = MY_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & 0x20000000) {   /* IMAGE_SCN_CNT_CODE */
            *va = sec[i].VirtualAddress;
            *size = sec[i].SizeOfRawData;
            *off = sec[i].PointerToRawData;
            for (uint32_t j = 0; j + 2 < *size; j++) {
                if (buf[*off + j] == 0x0F && buf[*off + j + 1] == 0x05 && buf[*off + j + 2] == 0xC3) {
                    *gadget = (uintptr_t)liveBase + *va + j;
                    return 1;
                }
            }
        }
    }
    return 0;
}

#endif /* PEPARSE_H */
