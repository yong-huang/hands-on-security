#!/usr/bin/env python3
"""05 · 数据包构造与嗅探工具（scapy）

用法:
    python3 packet_tool.py info                    # 免 root：本机接口 / 网关 / 网段
    python3 packet_tool.py craft                   # 免 root：构造 ARP/ICMP/TCP 包并反解析
    sudo python3 packet_tool.py arp-scan           # root：ARP 广播扫描本网段
    sudo python3 packet_tool.py ping-sweep         # root：ICMP 扫描本网段
    sudo python3 packet_tool.py sniff               # root：边抓边发，捕获自发的 ping

仅依赖 scapy；仅用于本机网段与已授权目标。发送原始包与抓包需要 root
（原始套接字 + /dev/bpf 都是特权资源）。
"""
import argparse
import ipaddress
import os
import re
import subprocess
import sys
import time

from scapy.all import ARP, ICMP, IP, TCP, AsyncSniffer, Ether, conf, get_if_hwaddr, sr, sr1, srp
from scapy.utils import hexdump

TESTNET_SRC = "192.0.2.10"      # RFC 5737 文档用地址：拿不到真实网卡信息时的占位
TESTNET_DST = "192.0.2.1"


def local_net():
    """读取默认出口网卡：接口名、IP、MAC、网关、子网（免 root）。"""
    iface, ip, gw = conf.route.route("0.0.0.0")
    mac = ""
    try:
        mac = get_if_hwaddr(iface)
    except Exception:
        pass
    net = None
    for tool in ("ifconfig", "/sbin/ifconfig"):   # root 下 PATH 可能不含 /sbin
        try:
            out = subprocess.run([tool, iface], capture_output=True, text=True, timeout=5).stdout
        except FileNotFoundError:
            continue
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", out)
        if m:
            mask = ipaddress.IPv4Address(int(m.group(2), 16))
            net = ipaddress.IPv4Network(f"{m.group(1)}/{mask}", strict=False)
        break
    return iface, ip, gw, mac, net


def require_root(cmd):
    if os.geteuid() != 0:
        print(f"[!] {cmd} 需要 root：原始套接字与 BPF 抓包都是特权资源，"
              f"用 sudo 重跑该命令。", file=sys.stderr)
        sys.exit(3)


def host_list(net):
    return [str(h) for h in net.hosts()]


# ---------------------------------------------------------------- info
def cmd_info(_args):
    iface, ip, gw, mac, net = local_net()
    print(f"[*] 默认出口 {iface}：{ip}  MAC {mac}")
    if net:
        print(f"[*] 网关 {gw}（子网 {net}，{net.num_addresses - 2} 个主机地址）")
    else:
        print(f"[*] 网关 {gw}（子网信息未取到）")
    role = "root" if os.geteuid() == 0 else "普通用户"
    print(f"[*] 权限：{role}（root 才能发原始包与抓包：sudo ./packet_tool.sh）")
    return 0


# ---------------------------------------------------------------- craft
def _craft_one(title, pkt, check):
    """打印分层字段 → 序列化 → 反解析；check(back) 返回证据文本（空串 = 失败）。"""
    print(f"\n=== {title} ===")
    pkt.show()                                   # 逐层展开每个字段
    raw = bytes(pkt)
    print(f"[*] 序列化：{len(raw)} 字节（网卡实发时会补到 60 字节）")
    hexdump(raw[:24])
    evidence = check(Ether(raw))
    print(f"[*] 反解析核对：{evidence or '失败'} {'✓' if evidence else '✗'}")
    return bool(evidence)


def cmd_craft(_args):
    _, ip, gw, mac, net = local_net()
    if not ip or not mac:
        ip, mac = TESTNET_SRC, "02:00:00:00:00:01"
    if not gw:
        gw = TESTNET_DST
    print(f"[*] 以本机 {ip} / {mac} 为源构造三个包（只构造，不发送——发送要 root）")

    ok = True
    ok &= _craft_one(
        "① ARP who-has：二层广播『谁是网关』——扫描的基石",
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=ip, pdst=gw),
        lambda back: f"op=who-has、pdst={gw}"
        if back[ARP].op == 1 and back[ARP].pdst == gw else "",
    )
    icmp = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=ip, dst=gw) / ICMP()
    raw = bytes(icmp)
    back = Ether(raw)                            # 先序列化再解析，校验和这时才可见
    ok &= _craft_one(
        "② ICMP echo-request（ping 的真身）",
        icmp,
        lambda _back: f"IP.chksum={hex(back[IP].chksum)}、ICMP.chksum={hex(back[ICMP].chksum)}"
        f"（构造时是 None，序列化才算）",
    )
    ok &= _craft_one(
        "③ TCP SYN（握手的第一步，这里不完成握手）",
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=ip, dst=gw) / TCP(dport=443, flags="S"),
        lambda back: f"flags=S、dport={back[TCP].dport}"
        if back[TCP].flags == "S" and back[TCP].dport == 443 else "",
    )
    print("\n[=] 构造演示完成：三个包都走通了「构造 → 序列化 → 反解析」"
          "，但都还没被发送")
    return 0 if ok else 1


# ---------------------------------------------------------------- arp-scan
def cmd_arp_scan(args):
    require_root("arp-scan")
    iface, ip, gw, mac, net = local_net()
    target = ipaddress.IPv4Network(args.target) if args.target else net
    if target is None:
        print("[!] 无法确定本网段，请用 --target 指定（如 192.168.1.0/24）", file=sys.stderr)
        return 1
    hosts = host_list(target)
    print(f"[*] ARP 扫描 {target}（广播 who-has × {len(hosts)}，收集 {args.timeout}s）")
    print(f"[*] 本机 MAC {mac}（自己不会回应自己的广播）")
    t0 = time.perf_counter()
    # promisc=False：macOS Wi-Fi 不支持混杂模式（BIOCPROMISC 报 ENOTSUP），
    # 且本实验只需要收「发给自己的应答」，不需要混杂
    ans, _ = srp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=ip, pdst=hosts),
                 iface=iface, timeout=args.timeout, verbose=0, promisc=False)
    rows = sorted({(r.psrc, r.hwsrc) for _, r in ans})
    for host, hw in rows:
        mark = "  ← 网关" if host == gw else ""
        print(f"[ARP] {host:<16} {hw}{mark}")
    print(f"[=] 应答 {len(rows)} 台，耗时 {time.perf_counter() - t0:.2f}s")
    return 0


# ---------------------------------------------------------------- ping-sweep
def cmd_ping_sweep(args):
    require_root("ping-sweep")
    iface, ip, gw, mac, net = local_net()
    target = ipaddress.IPv4Network(args.target) if args.target else net
    if target is None:
        print("[!] 无法确定本网段，请用 --target 指定（如 192.168.1.0/24）", file=sys.stderr)
        return 1
    hosts = host_list(target)
    print(f"[*] ICMP 扫描 {target}（echo-request × {len(hosts)}，超时 {args.timeout}s）")
    t0 = time.perf_counter()
    # sr 要「一组包」，且包列表模式下不能带 iface=（scapy 逐包选路，全在本网段 → en0）
    ans, _ = sr([IP(dst=h) / ICMP() for h in hosts], timeout=args.timeout,
                verbose=0, promisc=False)
    rows = [(recv.src, recv.time - sent.sent_time) for sent, recv in ans]
    rows.sort()
    for host, rtt in rows:
        mark = "  ← 本机" if host == ip else ("  ← 网关" if host == gw else "")
        print(f"[PING] {host:<16} {rtt:.3f}s{mark}")
    print(f"[=] 可达 {len(rows)} 台，耗时 {time.perf_counter() - t0:.2f}s")
    return 0


# ---------------------------------------------------------------- sniff
def cmd_sniff(args):
    require_root("sniff")
    seen = []
    t0 = time.perf_counter()
    print(f"[*] 抓包 {args.iface} filter={args.filter}：边抓边发 {args.send} 次 "
          f"ping 127.0.0.1（预计 {args.send * 2} 个 ICMP 包，目标 {args.count} 个）")

    def handle(pkt):
        if len(seen) < args.count:
            seen.append(pkt)
            print(f"[SNIFF] #{len(seen):02d} {pkt.summary()}", flush=True)

    sniffer = AsyncSniffer(iface=args.iface, filter=args.filter, prn=handle,
                           store=False, promisc=False)
    sniffer.start()
    try:
        for _ in range(args.send):
            sr1(IP(dst="127.0.0.1") / ICMP(), timeout=1, verbose=0)
            time.sleep(0.05)
    finally:
        deadline = time.time() + 3
        while len(seen) < args.count and time.time() < deadline:
            time.sleep(0.05)
        sniffer.stop()
    n = len(seen)
    print(f"[=] 捕获 {n} 个 ICMP 包（阈值 ≥10）"
          f"，耗时 {time.perf_counter() - t0:.2f}s")
    return 0 if n >= 10 else 1


# ---------------------------------------------------------------- main
def main() -> int:
    conf.verb = 0                                # scapy 自身的提示静音，输出归本工具管
    parser = argparse.ArgumentParser(
        description="数据包构造与嗅探工具：ARP 扫描 / ICMP 扫描 / BPF 抓包（仅限本机与授权目标）",
        epilog="示例: sudo python3 packet_tool.py arp-scan")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="打印本机接口/网关/网段（免 root）")
    p_info.set_defaults(func=cmd_info)

    p_craft = sub.add_parser("craft", help="构造 ARP/ICMP/TCP 包并反解析（免 root）")
    p_craft.set_defaults(func=cmd_craft)

    p_arp = sub.add_parser("arp-scan", help="ARP 广播扫描（需 root）")
    p_arp.add_argument("--target", help="目标网段，如 192.168.1.0/24（默认本网段）")
    p_arp.add_argument("--timeout", type=float, default=2.0, help="收集应答的秒数（默认 2）")
    p_arp.set_defaults(func=cmd_arp_scan)

    p_ping = sub.add_parser("ping-sweep", help="ICMP 扫描（需 root）")
    p_ping.add_argument("--target", help="目标网段（默认本网段）")
    p_ping.add_argument("--timeout", type=float, default=1.0, help="等待应答的秒数（默认 1）")
    p_ping.set_defaults(func=cmd_ping_sweep)

    p_sniff = sub.add_parser("sniff", help="边抓边发捕获自己的 ping（需 root）")
    p_sniff.add_argument("--iface", default="lo0", help="抓包网卡（默认 lo0 回环，最确定）")
    p_sniff.add_argument("--filter", default="icmp", help="BPF 过滤表达式（默认 icmp）")
    p_sniff.add_argument("--count", type=int, default=12, help="目标捕获数（默认 12）")
    p_sniff.add_argument("--send", type=int, default=6, help="发送 ping 的次数（默认 6）")
    p_sniff.set_defaults(func=cmd_sniff)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
