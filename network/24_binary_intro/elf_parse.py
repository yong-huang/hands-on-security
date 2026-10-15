#!/usr/bin/env python3
"""24 · 二进制静态分析入门 —— 纯 struct.unpack 手写的 ELF / Mach-O 解析器

用法:
    python3 elf_parse.py header   --file BIN                  # 头字段（与 readelf -h 对账）
    python3 elf_parse.py sections --file BIN [--limit N]      # 节表概览
    python3 elf_parse.py find-str --file BIN --str "TEXT"     # 关键字符串 → 文件偏移 → 虚拟地址
    python3 elf_parse.py macho    --file BIN                  # Mach-O 头（macOS 对照 otool -h）

不依赖 readelf/otool：全部字段由 struct.unpack 手工拆出；
find-str 用节表的 sh_addr/sh_offset 完成「文件偏移 → 虚拟地址」映射。
"""
import argparse
import struct
import sys
from pathlib import Path

MACHINES = {
    0x03: "Intel 80386", 0x28: "ARM", 0x3E: "Advanced Micro Devices X86-64",
    0xB7: "AArch64", 0xF3: "RISC-V",
}
ETYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
OSABI = {0: "UNIX - System V", 3: "UNIX - GNU", 9: "UNIX - FreeBSD"}
SHTYPES = {1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 8: "NOBITS", 9: "REL"}


def read_elf_header(data: bytes):
    """拆 ELF 头：返回字段字典；非 ELF 抛 ValueError。"""
    if data[:4] != b"\x7fELF":
        raise ValueError("不是 ELF 文件（magic 不符）")
    ei_class, ei_data = data[4], data[5]
    if (ei_class, ei_data) not in ((2, 1), (1, 1), (2, 2), (1, 2)):
        raise ValueError(f"暂不支持的 class/endian 组合: {ei_class}/{ei_data}")
    end = "<" if ei_data == 1 else ">"
    if ei_class == 2:
        fmt = end + "HHIQQQIHHHHHH"
        raw = struct.unpack(fmt, data[16:64])
    else:
        fmt = end + "HHIIIIIHHHHHH"
        raw = struct.unpack(fmt, data[16:52])
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = raw
    return {
        "magic": " ".join(f"{b:02x}" for b in data[:16]),
        "class": "ELF64" if ei_class == 2 else "ELF32",
        "data": "2's complement, little endian" if ei_data == 1 else "2's complement, big endian",
        "osabi": OSABI.get(data[7], f"<unknown: {data[7]}>"),
        "type": ETYPES.get(e_type, str(e_type)),
        "machine": MACHINES.get(e_machine, f"<unknown: {e_machine:#x}>"),
        "entry": e_entry,
        "shoff": e_shoff, "shentsize": e_shentsize, "shnum": e_shnum,
        "shstrndx": e_shstrndx, "bits": 64 if ei_class == 2 else 32, "endian": end,
    }


def read_sections(data: bytes, hdr):
    """拆节表：返回 [ {name, type, addr, offset, size} ... ]。"""
    secs = []
    for i in range(hdr["shnum"]):
        off = hdr["shoff"] + i * hdr["shentsize"]
        if hdr["bits"] == 64:
            name, typ, flags, addr, soff, size, link, info, align, entsize = \
                struct.unpack(hdr["endian"] + "IIQQQQIIQQ", data[off:off + 64])
        else:
            name, typ, flags, addr, soff, size, link, info, align, entsize = \
                struct.unpack(hdr["endian"] + "IIIIIIIIII", data[off:off + 40])
        secs.append({"name_off": name, "type": typ, "addr": addr,
                     "offset": soff, "size": size})
    # 解出节名（shstrtab）
    if 0 <= hdr["shstrndx"] < len(secs):
        strtab = secs[hdr["shstrndx"]]
        blob = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
        for s in secs:
            end = blob.find(b"\x00", s["name_off"])
            s["name"] = blob[s["name_off"]:end].decode("utf-8", "replace") if end >= 0 else "?"
    return secs


def cmd_header(a):
    hdr = read_elf_header(Path(a.file).read_bytes())
    print(f"[elf] Magic   {hdr['magic']}")
    print(f"[elf] Class   {hdr['class']}")
    print(f"[elf] Data    {hdr['data']}")
    print(f"[elf] OS/ABI  {hdr['osabi']}")
    print(f"[elf] Type    {hdr['type']}")
    print(f"[elf] Machine {hdr['machine']}")
    print(f"[elf] Entry   0x{hdr['entry']:x}")
    return 0


def cmd_sections(a):
    data = Path(a.file).read_bytes()
    hdr = read_elf_header(data)
    print(f"[elf] 共 {hdr['shnum']} 个节（前 {a.limit} 个）：")
    for i, s in enumerate(read_sections(data, hdr)[:a.limit]):
        tname = SHTYPES.get(s["type"], str(s["type"]))
        print(f"  [{i:2d}] {s['name']:<20} {tname:<9} addr=0x{s['addr']:08x} "
              f"off=0x{s['offset']:06x} size=0x{s['size']:x}")
    return 0


def cmd_find_str(a):
    data = Path(a.file).read_bytes()
    hdr = read_elf_header(data)
    secs = read_sections(data, hdr)
    needle = a.str.encode("utf-8")
    hits = 0
    pos = data.find(needle)
    while pos >= 0:
        sec = next((s for s in secs
                    if s["type"] != 8 and s["offset"] <= pos < s["offset"] + s["size"]), None)
        if sec:
            va = sec["addr"] + (pos - sec["offset"])
            print(f"[find] \"{a.str}\" 文件偏移 0x{pos:x}（strings -t x 同口径）"
                  f" → 节 {sec['name']} → 虚拟地址 0x{va:x}")
        else:
            print(f"[find] \"{a.str}\" 文件偏移 0x{pos:x}（不在任何已分配节内）")
        hits += 1
        pos = data.find(needle, pos + 1)
    if not hits:
        print(f"[find] 未找到 \"{a.str}\"")
        return 1
    return 0


def cmd_macho(a):
    data = Path(a.file).read_bytes()
    magic = data[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        bits, fmt = 64, "<IiiIIIII"
    elif magic == b"\xce\xfa\xed\xfe":
        bits, fmt = 32, "<IiiIIII"
    elif magic == b"\xca\xfe\xba\xbe":
        print("[macho] Fat 二进制（多架构打包）——本实验只解析单架构头")
        return 0
    else:
        raise SystemExit(f"[!] 不是 Mach-O 文件（magic={magic.hex()}）")
    m, cputype, cpusubtype, ftype, ncmds, sizeofcmds, flags = struct.unpack(fmt, data[:28 if bits == 32 else 32])[:7]
    cpu_names = {16777223: "X86_64", 16777228: "ARM64", 12: "ARM", 7: "I386"}
    ftypes = {1: "OBJECT", 2: "EXECUTE", 6: "DYLIB", 8: "BUNDLE"}
    print(f"[macho] Magic     0x{m:08x}（Mach-O {bits} 位）")
    print(f"[macho] CPUType   {cputype} ({cpu_names.get(cputype, '?')})")
    print(f"[macho] FileType  {ftype} ({ftypes.get(ftype, '?')})")
    print(f"[macho] NCmds     {ncmds}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="ELF/Mach-O 手工解析器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p0 = sub.add_parser("header")
    p0.add_argument("--file", required=True)
    p0.set_defaults(func=cmd_header)

    p1 = sub.add_parser("sections")
    p1.add_argument("--file", required=True)
    p1.add_argument("--limit", type=int, default=40)
    p1.set_defaults(func=cmd_sections)

    p2 = sub.add_parser("find-str")
    p2.add_argument("--file", required=True)
    p2.add_argument("--str", required=True)
    p2.set_defaults(func=cmd_find_str)

    p3 = sub.add_parser("macho")
    p3.add_argument("--file", required=True)
    p3.set_defaults(func=cmd_macho)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
