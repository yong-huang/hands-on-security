#!/usr/bin/env bash
# =============================================================================
# 24 · 二进制静态分析入门 —— 手写解析器 / readelf 逐字段对账 / 字符串寻址 / Mach-O 对照
# 用法: ./binary_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: Docker（首次构建 alpine+gcc+binutils 容器）；宿主机 clang（Xcode CLT）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
IMG="hosec24-build"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "构建编译容器 → 产 ELF（容器内交叉）与 Mach-O（宿主 clang）+ 对照材料"
    command -v docker > /dev/null || die "缺少 docker"
    docker info > /dev/null 2>&1 || die "Docker 未运行（先启动 OrbStack / Docker Desktop）"
    command -v clang > /dev/null || die "缺少 clang（安装 Xcode CLT：xcode-select --install）"
    mkdir -p "$ART"
    docker build -q -t "$IMG" configs/ > /dev/null
    docker run --rm -v "$PWD/configs:/src:ro" -v "$PWD/$ART:/out" "$IMG" sh -c '
        gcc -no-pie -O0 -o /out/crackme /src/crackme.c &&
        readelf -h /out/crackme > /out/readelf-h.txt &&
        readelf -S /out/crackme > /out/readelf-S.txt &&
        objdump -d /out/crackme > /out/objdump-d.txt &&
        objdump -s -j .rodata /out/crackme > /out/objdump-rodata.txt &&
        strings -t x /out/crackme > /out/strings.txt'
    ok "ELF crackme 已编译：$(file -b "$ART/crackme" | cut -d, -f1-2)"
    clang configs/crackme.c -o "$ART/crackme-macho"
    otool -hv "$ART/crackme-macho" > "$ART/otool-hv.txt"
    ok "Mach-O 对照件已编译（同一份源码，宿主 clang）——两种格式同源"
}

do_observe() {
    step "observe" "① 手写解析器 vs readelf -h：七个字段逐一对账"
    "$PY" elf_parse.py header --file "$ART/crackme" | tee "$ART/header.out"
    "$PY" - "$ART/header.out" "$ART/readelf-h.txt" <<'PYEOF' || die "与 readelf -h 对账不一致"
import sys
ours = {}
for l in open(sys.argv[1], encoding="utf-8"):
    if l.startswith("[elf] "):
        k, v = l[6:].split(None, 1)
        ours[k] = v.strip()
ref = {}
for l in open(sys.argv[2], encoding="utf-8"):
    if ":" in l:
        k, _, v = l.partition(":")
        ref[k.strip()] = v.strip()
checks = [("Magic", ours["Magic"], ref["Magic"]),
          ("Class", ours["Class"], ref["Class"]),
          ("Data", ours["Data"], ref["Data"]),
          ("OS/ABI", ours["OS/ABI"], ref["OS/ABI"]),
          ("Type", ours["Type"], ref["Type"].split()[0]),
          ("Machine", ours["Machine"], ref["Machine"]),
          ("Entry", ours["Entry"], ref["Entry point address"])]
bad = [(k, a, b) for k, a, b in checks
       if not (int(a, 16) == int(b, 16) if k == "Entry" else a == b)]
for k, a, b in checks:
    print(f"  {k:<7} 自研={a}  readelf={b}")
sys.exit(1 if bad else 0)
PYEOF
    ok "7/7 字段逐字一致（magic/class/data/osabi/type/machine/entry，验收 ①）"

    step "observe" "② 关键字符串寻址：strings 偏移 → 节表映射 → 虚拟地址（objdump 独立复核）"
    "$PY" elf_parse.py find-str --file "$ART/crackme" \
        --str "ACCESS GRANTED! flag=HOSEC24-STATIC-OK" | tee "$ART/find.out"
    "$PY" elf_parse.py find-str --file "$ART/crackme" --str "hosec24-gate-key" | tee -a "$ART/find.out"
    grep -q "ACCESS GRANTED" "$ART/find.out" || die "未定位成功串"
    "$PY" - "$ART/find.out" "$ART/strings.txt" "$ART/objdump-rodata.txt" <<'PYEOF' || die "地址复核失败"
import re, sys
find_txt = open(sys.argv[1], encoding="utf-8").read()
strs = open(sys.argv[2], encoding="utf-8").read()
od = open(sys.argv[3], encoding="utf-8").read()
needle = "ACCESS GRANTED! flag=HOSEC24-STATIC-OK"
m = re.search(r"文件偏移 0x([0-9a-f]+)", find_txt)
off = int(m.group(1), 16)
sm = re.search(r"^\s*([0-9a-f]+)\s+" + re.escape("ACCESS GRANTED"), strs, re.M)
assert sm and int(sm.group(1), 16) == off, "strings -t x 的偏移与自研不一致"
va = int(re.search(r"虚拟地址 0x([0-9a-f]+)", find_txt).group(1), 16)
buf = {}
for row in re.finditer(r"^\s*([0-9a-f]{4,16})\s+((?:[0-9a-f]{2,8}\s+){1,4})", od, re.M):
    addr = int(row.group(1), 16)
    data = bytes.fromhex(row.group(2).replace(" ", ""))
    for i, b in enumerate(data):
        buf[addr + i] = b
seq = bytes(buf.get(va + i) for i in range(len(needle)))
assert seq == needle.encode(), f"objdump 在 0x{va:x} 处字节不符：{seq[:16]!r}"
print(f"  ✓ strings 偏移一致（0x{off:x}）")
print(f"  ✓ objdump .rodata 在 0x{va:x} 的字节与字符串逐字吻合（独立复核）")
PYEOF
    docker run --rm -v "$PWD/$ART:/out:ro" "$IMG" sh -c '/out/crackme hosec24-gate-key' \
        | sed 's/^/  ↳ 行为验证：/'
    ok "成功串定位并双重复核；同句口令也是明文——静态直接拿走（验收 ②）"

    step "observe" "③ Mach-O 头对照：同一份源码，宿主 clang 产物 vs otool -hv"
    "$PY" elf_parse.py macho --file "$ART/crackme-macho" | tee "$ART/macho.out"
    "$PY" - "$ART/macho.out" "$ART/otool-hv.txt" <<'PYEOF' || die "与 otool 对账不一致"
import re, sys
ours = {}
for l in open(sys.argv[1], encoding="utf-8"):
    if l.startswith("[macho] "):
        k, v = l[8:].split(None, 1)
        ours[k] = v.strip()
row = None
for l in open(sys.argv[2], encoding="utf-8"):
    m = re.match(r"^(MH_MAGIC\w*|0x[0-9a-f]+)\s+(\S+)\s+\S+\s+0x\S+\s+(\S+)\s+(\d+)", l)
    if m:
        row = m
        break
assert row, "未解析到 otool -hv 数据行"
magic_map = {"MH_MAGIC_64": 0xfeedfacf, "MH_MAGIC": 0xfeedface}
o_magic, o_cpu, o_ftype, o_ncmds = row.group(1), row.group(2), row.group(3), int(row.group(4))
ok = (magic_map.get(o_magic, -1) == int(ours["Magic"].split("（")[0], 16)
      and f"({o_cpu})" in ours["CPUType"]
      and f"({o_ftype})" in ours["FileType"]
      and int(ours["NCmds"]) == o_ncmds)
print(f"  otool：magic={o_magic} cpu={o_cpu} filetype={o_ftype} ncmds={o_ncmds}")
sys.exit(0 if ok else 1)
PYEOF
    ok "Mach-O 四字段与 otool 一致——ELF 与 Mach-O 同源不同形"
}

do_clean() {
    step "clean" "清理生成物（二进制、对照材料与输出）"
    rm -rf "$ART"
    ok "产物已清；编译镜像 ${IMG} 保留（重跑秒级）"
}

main() {
    local target="${1:-all}"
    case "$target" in
        apply)   do_apply ;;
        observe) do_observe ;;
        clean)   do_clean ;;
        all)     do_apply; do_observe; do_clean ;;
        *) echo "可用: apply | observe | clean | all" >&2; exit 1 ;;
    esac
}
main "$@"
