#!/usr/bin/env python3
"""gen_test_pe.py - craft a minimal PE64 whose .text mimics ntdll stub layout
Used by test_parser.c to validate peparse.h logic without a Windows box.

Stub forms exercised (real ntdll Win10/11 patterns):
  - "mov r10, rcx; mov eax, imm32"   (4C 8B D1 B8 imm)  - 5 functions
  - "jmp rel32" E9 thunk -> above form                    - 1 function
  - plain "mov eax, imm32" (B8 imm)                       - 1 function
Gadget: a "syscall; ret" (0F 05 C3) at .text+0x300
"""
import struct
import sys

NAMES = [b"ZwAllocateVirtualMemory", b"ZwWriteVirtualMemory", b"ZwProtectVirtualMemory",
         b"ZwQueueApcThread", b"ZwResumeThread", b"ZwQueryInformationProcess",
         b"ZwReadVirtualMemory"]
SSNS = [0x18, 0x3A, 0x50, 0x45, 0x52, 0x19, 0x3F]   # real Win10 x64 SSNs
E9_IDX = 3      # ZwQueueApcThread -> E9 thunk
B8_IDX = 6      # ZwReadVirtualMemory -> plain B8

TEXT_RVA = 0x1000
TEXT_RAW = 0x400
TEXT_SIZE = 0x1000

STUB_BASE = TEXT_RVA + 0x000
THUNK_TGT = TEXT_RVA + 0x200
GADGET_AT = TEXT_RVA + 0x300
EXP_DIR   = TEXT_RVA + 0x380
NAME_PTRS = TEXT_RVA + 0x400
ORDINALS  = TEXT_RVA + 0x420
FUNC_PTRS = TEXT_RVA + 0x430
NAME_STR  = TEXT_RVA + 0x450


def rva_to_idx(rva):
    """text-array index for a given RVA (text array maps 1:1 to RVA space)"""
    return rva - TEXT_RVA


text = bytearray(TEXT_SIZE)

# stubs
for i in range(7):
    stub = STUB_BASE + i * 0x20
    if i == E9_IDX:
        rel = THUNK_TGT - (stub + 5)
        text[rva_to_idx(stub):rva_to_idx(stub) + 5] = b"\xE9" + struct.pack("<i", rel)
    elif i == B8_IDX:
        text[rva_to_idx(stub):rva_to_idx(stub) + 5] = b"\xB8" + struct.pack("<I", SSNS[i])
    else:
        text[rva_to_idx(stub):rva_to_idx(stub) + 8] = b"\x4C\x8B\xD1\xB8" + struct.pack("<I", SSNS[i])

# E9 thunk target: mov r10,rcx; mov eax,imm (ssn of idx 3)
text[rva_to_idx(THUNK_TGT):rva_to_idx(THUNK_TGT) + 8] = b"\x4C\x8B\xD1\xB8" + struct.pack("<I", SSNS[E9_IDX])

# syscall;ret gadget
text[rva_to_idx(GADGET_AT):rva_to_idx(GADGET_AT) + 3] = b"\x0F\x05\xC3"

# export directory
exp = struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<HH", 0, 0)
exp += struct.pack("<I", 0)                                   # Name
exp += struct.pack("<I", 0)                                   # Base
exp += struct.pack("<I", 7)                                   # NumberOfFunctions
exp += struct.pack("<I", 7)                                   # NumberOfNames
exp += struct.pack("<I", FUNC_PTRS)                           # AddressOfFunctions
exp += struct.pack("<I", NAME_PTRS)                           # AddressOfNames
exp += struct.pack("<I", ORDINALS)                            # AddressOfNameOrdinals
assert len(exp) == 40
text[rva_to_idx(EXP_DIR):rva_to_idx(EXP_DIR) + 40] = exp

# name pointer array
off = 0
stroffs = []
for n in NAMES:
    stroffs.append(off)
    off += len(n) + 1
for i, n in enumerate(NAMES):
    text[rva_to_idx(NAME_PTRS) + i * 4:rva_to_idx(NAME_PTRS) + i * 4 + 4] = \
        struct.pack("<I", NAME_STR + stroffs[i])

# ordinal array
for i in range(7):
    text[rva_to_idx(ORDINALS) + i * 2:rva_to_idx(ORDINALS) + i * 2 + 2] = struct.pack("<H", i)

# function pointer array -> stub RVAs
for i in range(7):
    text[rva_to_idx(FUNC_PTRS) + i * 4:rva_to_idx(FUNC_PTRS) + i * 4 + 4] = \
        struct.pack("<I", STUB_BASE + i * 0x20)

# name strings
pos = rva_to_idx(NAME_STR)
for n in NAMES:
    text[pos:pos + len(n)] = n
    pos += len(n) + 1

# ---- headers ----
dos = bytearray(0x80)
dos[0:2] = b"MZ"
dos[0x3C:0x40] = struct.pack("<I", 0x80)

nt = bytearray(4 + 20 + 0xF0)
nt[0:4] = b"PE\x00\x00"
nt[4:6] = struct.pack("<H", 0x8664)          # machine x64 (file hdr starts after sig)
nt[6:8] = struct.pack("<H", 1)               # sections
nt[20:22] = struct.pack("<H", 0xF0)          # SizeOfOptionalHeader
nt[22:24] = struct.pack("<H", 0x2022)        # characteristics
opt = 4 + 20
nt[opt + 0:opt + 2] = struct.pack("<H", 0x20B)      # PE32+ magic
nt[opt + 0x30:opt + 0x34] = struct.pack("<I", 0x1000)  # SectionAlignment
nt[opt + 0x34:opt + 0x38] = struct.pack("<I", 0x400)   # FileAlignment
nt[opt + 0x38:opt + 0x3C] = struct.pack("<I", 0x2000)  # SizeOfImage
nt[opt + 0x3C:opt + 0x40] = struct.pack("<I", 0x400)   # SizeOfHeaders
nt[opt + 0x44:opt + 0x46] = struct.pack("<H", 3)       # Subsystem (CUI)
nt[opt + 0x6C:opt + 0x70] = struct.pack("<I", 16)      # NumberOfRvaAndSizes
nt[opt + 0x70:opt + 0x78] = struct.pack("<II", EXP_DIR, 0x100)  # DataDirectory[0]

sec = bytearray(40)
sec[0:8] = b".text\x00\x00\x00"
sec[8:12] = struct.pack("<I", TEXT_SIZE)     # VirtualSize
sec[12:16] = struct.pack("<I", TEXT_RVA)     # VirtualAddress
sec[16:20] = struct.pack("<I", TEXT_SIZE)    # SizeOfRawData
sec[20:24] = struct.pack("<I", TEXT_RAW)     # PointerToRawData
sec[36:40] = struct.pack("<I", 0x60000020)   # code section

out = dos + nt + sec
out += b"\x00" * (TEXT_RAW - len(out))
out += text

out_path = sys.argv[1] if len(sys.argv) > 1 else "test_ntdll.bin"
open(out_path, "wb").write(out)
print(f"[+] wrote {out_path} ({len(out)} bytes): 7 exports, E9 thunk, B8 stub, gadget @ 0x{GADGET_AT:X}")
