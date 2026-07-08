#!/usr/bin/env python3
from pathlib import Path
import struct
import sys

MOV_W0_0 = 0x52800000

def parse_u32(value):
    return int(value, 0) & 0xffffffff

def parse_off(value):
    return int(value, 0)

def read_u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

def write_u32(buf, off, value):
    struct.pack_into("<I", buf, off, value)

def main(argv):
    if len(argv) not in (6, 7):
        print("usage: pacsafe_sigcheck_zero.py <input> <output> <patch_off> <expected_old> <retab_off> [expected_retab]")
        return 2

    src = Path(argv[1])
    dst = Path(argv[2])
    patch_off = parse_off(argv[3])
    expected_old = parse_u32(argv[4])
    retab_off = parse_off(argv[5])
    expected_retab = parse_u32(argv[6]) if len(argv) == 7 else 0xd65f0fff

    if not src.is_file():
        print(f"missing input: {src}")
        return 1

    buf = bytearray(src.read_bytes())

    for name, off in (("patch", patch_off), ("retab", retab_off)):
        if off < 0 or off + 4 > len(buf):
            print(f"{name} offset out of range: 0x{off:x}")
            return 1

    old = read_u32(buf, patch_off)
    retab = read_u32(buf, retab_off)

    print(f"patch_off=0x{patch_off:x}")
    print(f"old=0x{old:08x}")
    print(f"expected_old=0x{expected_old:08x}")
    print(f"new=0x{MOV_W0_0:08x}")
    print(f"retab_off=0x{retab_off:x}")
    print(f"retab=0x{retab:08x}")
    print(f"expected_retab=0x{expected_retab:08x}")

    if old != expected_old:
        print("refusing to patch: old instruction mismatch")
        return 1

    if retab != expected_retab:
        print("refusing to patch: return instruction mismatch")
        return 1

    write_u32(buf, patch_off, MOV_W0_0)
    dst.write_bytes(buf)
    print(f"wrote {dst}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
