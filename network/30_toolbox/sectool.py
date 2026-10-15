#!/usr/bin/env python3
# =============================================================================
# 30 · sectool —— 个人安全工具箱 CLI（收编系列五件套）
#   scan-port   端口扫描   ← 01_tcp_port_scanner/port_scanner.py
#   enum-dns    子域枚举   ← 02_dns_enum/dns_enum.py
#   dir-brute   目录爆破   ← 03_dir_brute/dir_brute.py
#   crack-hash  哈希破解   ← 07_hash_crack/hash_cracker.py
#   log-audit   日志审计   ← 19_log_audit/log_audit.py
#   统一约定：结果行两空格缩进；末行 [sectool] 汇总；
#             退出码 0=完成无发现 / 1=完成有发现 / 2=参数错 / 3=环境错
# =============================================================================
import argparse
import contextlib
import io
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

NET = Path(__file__).resolve().parent.parent
for lab in ("01_tcp_port_scanner", "02_dns_enum", "03_dir_brute",
            "07_hash_crack", "19_log_audit"):
    sys.path.insert(0, str(NET / lab))

import dir_brute      # noqa: E402
import dns_enum       # noqa: E402
import hash_cracker   # noqa: E402
import log_audit      # noqa: E402
import port_scanner   # noqa: E402

DEFAULT_SUBDOMAINS = ["www", "mail", "api", "blog", "shop", "ns1", "dev", "test"]


# ---------------------------------------------------------------- 子命令实现
def sub_scan_port(args):
    ip = socket.gethostbyname(args.target)
    ports = port_scanner.parse_ports(args.ports)
    limiter = port_scanner.RateLimiter(args.rate)
    found = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = [pool.submit(port_scanner.scan_one, ip, p, args.timeout, limiter)
                for p in ports]
        for f in as_completed(futs):
            r = f.result()
            if r:
                found.append(r)
    for port, banner in sorted(found):
        print(f"  {port:<6} open" + (f"  {banner}" if banner else ""))
    return len(found)


def sub_enum_dns(args):
    words = DEFAULT_SUBDOMAINS
    if args.wordlist:
        words = [w.strip() for w in Path(args.wordlist).read_text(encoding="utf-8").splitlines()
                 if w.strip() and not w.startswith("#")]
    resolver = dns_enum.make_resolver(args.resolver, args.port, args.timeout)
    apex = dns_enum.collect_apex(resolver, args.domain)
    for t in ("NS", "MX", "TXT"):
        vals = apex.get(t) or []
        print(f"  {t:<4} {', '.join(vals) if vals else '—'}")
    hits = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = {pool.submit(dns_enum.probe_subdomain, resolver, f"{w}.{args.domain}"): w
                for w in words}
        for f in as_completed(futs):
            r = f.result()
            if r:
                hits.append(r)
    for name, typ, value in sorted(hits):
        print(f"  {name:<22} {typ:<5} {value}")
    return len(hits)


def sub_dir_brute(args):
    words = dir_brute.load_words(args.wordlist)
    whitelist = {int(s) for s in args.status.split(",")}
    http = dir_brute.Http(args.timeout)
    baseline = None
    if not args.no_filter:
        baseline = dir_brute.soft404_baseline(http, args.target, args.tol)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), ThreadPoolExecutor(max_workers=args.threads) as pool:
        hits, _ = dir_brute.scan(http, pool, words, args.target, whitelist, baseline)
    for line in buf.getvalue().splitlines():
        print(f"  {line}")
    return len(hits)


def sub_crack_hash(args):
    ns = argparse.Namespace(hashfile=args.hashfile, wordlist=args.wordlist,
                            rules=args.rules, threads=args.threads)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hash_cracker.cmd_crack(ns)
    out = buf.getvalue()
    for line in out.splitlines():
        print(f"  {line}")
    m = re.search(r"破解 (\d+)/", out)
    return int(m.group(1)) if m else 0


def sub_log_audit(args):
    events = log_audit.read_events(args.log)
    findings = log_audit.apply_rules(events, args.min_fails, args.window)
    print(f"  输入 {Path(args.log).name}：{len(events)} 条事件解析成功")
    for ip, rid, msg in findings:
        print(f"  [{rid}] {msg}（来源 {ip}）")
    return len(findings)


# ---------------------------------------------------------------- 参数与调度
def build_parser():
    ap = argparse.ArgumentParser(
        prog="sectool",
        description="个人安全工具箱：五件工具，一个入口（仅限本地/授权目标）",
        epilog="退出码：0 完成无发现 / 1 完成有发现 / 2 参数错 / 3 运行环境错")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="<子命令>")

    p = sub.add_parser("scan-port", help="TCP 端口扫描（工具 01）")
    p.add_argument("target", help="目标 IP 或主机名")
    p.add_argument("-p", "--ports", default="1-1024", help="端口表达式（默认 1-1024）")
    p.add_argument("-t", "--threads", type=int, default=100)
    p.add_argument("-T", "--timeout", type=float, default=0.5)
    p.add_argument("--rate", type=int, default=0, help="全局限速（次/秒，0=不限）")
    p.set_defaults(fn=sub_scan_port)

    p = sub.add_parser("enum-dns", help="子域枚举（工具 02）")
    p.add_argument("domain", help="目标域名，如 lab.local")
    p.add_argument("--resolver", help="DNS 服务器 IP（默认系统解析器）")
    p.add_argument("--port", type=int, default=None, help="DNS 端口（默认 53）")
    p.add_argument("-w", "--wordlist", help="子域字典（默认内置 8 词）")
    p.add_argument("-t", "--threads", type=int, default=8)
    p.add_argument("-T", "--timeout", type=float, default=3.0)
    p.set_defaults(fn=sub_enum_dns)

    p = sub.add_parser("dir-brute", help="目录爆破（工具 03）")
    p.add_argument("target", help="目标基址，如 http://127.0.0.1:8821")
    p.add_argument("-w", "--wordlist", required=True, help="字典文件")
    p.add_argument("-t", "--threads", type=int, default=20)
    p.add_argument("-s", "--status", default="200,204,301,302,307,401,403,405",
                   help="命中状态码集合")
    p.add_argument("--tol", type=int, default=10, help="软 404 过滤容差（字节）")
    p.add_argument("--no-filter", action="store_true", help="关闭软 404 过滤")
    p.add_argument("-T", "--timeout", type=float, default=3.0)
    p.set_defaults(fn=sub_dir_brute)

    p = sub.add_parser("crack-hash", help="哈希破解（工具 07）")
    p.add_argument("hashfile", help="目标文件（每行 algo:hash）")
    p.add_argument("-w", "--wordlist", required=True)
    p.add_argument("-r", "--rules", action="store_true", help="开启规则变换")
    p.add_argument("-t", "--threads", type=int, default=8)
    p.set_defaults(fn=sub_crack_hash)

    p = sub.add_parser("log-audit", help="日志审计（工具 19）")
    p.add_argument("--log", required=True, help="ssh 认证日志文件")
    p.add_argument("--min-fails", type=int, default=30, help="窗口内失败次数阈值")
    p.add_argument("--window", type=int, default=60, help="检测窗口秒数")
    p.set_defaults(fn=sub_log_audit)
    return ap


def main():
    args = build_parser().parse_args()
    try:
        n = args.fn(args)
    except (OSError, ValueError) as e:
        print(f"[sectool] 运行环境错误：{e}", file=sys.stderr)
        return 3
    code = 1 if n else 0
    print(f"[sectool] {args.cmd} 完成：发现 {n} 项 → 退出码 {code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
