#!/usr/bin/env python3
"""02 · 子域名与 DNS 信息收集器

用法:
    python3 dns_enum.py <域名> [--resolver IP] [--port 端口] [-w 字典文件] [-t 线程数]
示例:
    python3 dns_enum.py lab.local --resolver 127.0.0.1 --port 5300   # 本实验测试域
    python3 dns_enum.py example.com --no-enum --no-axfr              # 只看 NS/MX/TXT

能力: 内置字典枚举子域（A/CNAME）、查询 NS/MX/TXT、尝试 AXFR 区域传送。
只依赖 dnspython；仅用于本地靶场与已授权目标。
"""
import argparse
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

# 内置常见子域字典：覆盖建站、邮件、接口、环境、运维等高频命名
# （教学用最小字典；实战请用 SecLists 等大字典，以 -w 指定）
BUILTIN_WORDLIST = [
    "www", "mail", "api", "blog", "shop", "dev", "test", "staging", "admin",
    "vpn", "ftp", "git", "docs", "cdn", "static", "portal", "app", "db",
    "smtp", "imap", "login", "monitor", "internal", "beta", "m",
]

TIMEOUTS = {"n": 0}                    # 超时计数：超时 ≠ 不存在，汇总时提示
_tlock = threading.Lock()


def make_resolver(server, port, timeout):
    """构造解析器；server 为空时读系统配置（/etc/resolv.conf）。"""
    r = dns.resolver.Resolver(configure=server is None)
    if server:
        r.nameservers = [server]          # 只问指定服务器，避免被系统解析器污染
    r.port = port
    r.timeout = timeout                   # 单次查询等待
    r.lifetime = timeout * 2              # 一次解析（含重试）的总预算
    return r


def query(resolver, name, rdtype):
    """查一类记录，返回 rdata 文本列表；不存在返回 []，超时单独计数。"""
    try:
        ans = resolver.resolve(name, rdtype)
    except dns.exception.Timeout:              # 超时 ≠ 不存在：结果不可信，单独计数
        with _tlock:
            TIMEOUTS["n"] += 1
        return []
    except dns.exception.DNSException:
        return []
    return [rr.to_text() for rr in ans]


def probe_subdomain(resolver, name):
    """探测一个子域：返回 (name, 类型, 值)；不存在返回 None。"""
    try:
        ans = resolver.resolve(name, "A")      # dnspython 会自动沿 CNAME 链找到 A
    except dns.resolver.NoAnswer:              # 名字存在但没有 A
        cname = query(resolver, name, "CNAME")
        if cname:                              # 悬空 CNAME：别名在、链尾无 A
            return (name, "CNAME", ", ".join(cname))
        for t in ("AAAA", "TXT", "MX", "NS"):  # 仅其他类型的名字：记「存在」不丢
            if query(resolver, name, t):
                return (name, t, "（存在，无 A 记录）")
        return None
    except dns.exception.Timeout:              # 超时 ≠ 不存在——单独计数
        with _tlock:
            TIMEOUTS["n"] += 1
        return None
    except dns.exception.DNSException:         # NXDOMAIN / 服务器无响应
        return None
    a_text = ", ".join(rr.to_text() for rr in ans.rrset)
    # canonical_name 与查询名不同 ⇒ 中间走过 CNAME 别名链（如 shop → www）
    if str(ans.canonical_name).rstrip(".") != name.rstrip("."):
        cname = query(resolver, name, "CNAME") or [str(ans.canonical_name)]
        return (name, "CNAME", f"{', '.join(cname)}（A: {a_text}）")
    return (name, "A", a_text)


def collect_apex(resolver, domain):
    """采集区顶点（apex）的 NS / MX / TXT 三类记录。"""
    return {t: query(resolver, domain, t) for t in ("NS", "MX", "TXT")}


def resolve_ns_ips(resolver, domain):
    """把 NS 主机名解析成 IP（去重保序），供 AXFR 直连使用。"""
    ips = []
    for ns in query(resolver, domain, "NS"):
        try:
            for rr in resolver.resolve(ns.rstrip("."), "A"):
                ip = rr.to_text()
                if ip not in ips:
                    ips.append(ip)
        except dns.exception.DNSException:
            continue
    return ips


def try_axfr(server, domain, port, timeout):
    """尝试区域传送：成功返回 (记录列表, None)，失败返回 (None, 原因)。"""
    try:
        z = dns.zone.from_xfr(dns.query.xfr(server, domain, port=port, timeout=timeout))
    except dns.exception.DNSException as e:
        return None, type(e).__name__
    except OSError as e:
        return None, str(e)
    rows = []
    for name, ttl, rdata in z.iterate_rdatas():
        fqdn = name.derelativize(z.origin)     # iterate 给的是相对名，补全成 FQDN
        rows.append((str(fqdn), ttl,
                     dns.rdatatype.to_text(rdata.rdtype),
                     rdata.to_text(origin=z.origin, relativize=False)))  # RDATA 里的域名补全域
    rows.sort(key=lambda r: (r[0], r[2]))
    return rows, None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="子域名枚举 + NS/MX/TXT 查询 + AXFR 区域传送尝试（仅限本地/授权目标）",
        epilog="示例: python3 dns_enum.py lab.local --resolver 127.0.0.1 --port 5300")
    parser.add_argument("domain", help="目标域名，如 lab.local")
    parser.add_argument("--resolver", help="DNS 服务器 IP（默认用系统解析器）")
    parser.add_argument("--port", type=int, default=None,
                        help="DNS 服务器端口（默认 53，需配合 --resolver）")
    parser.add_argument("-w", "--wordlist", help="自定义子域字典文件（每行一个，# 开头为注释）")
    parser.add_argument("-t", "--threads", type=int, default=20, help="枚举线程数（默认 20）")
    parser.add_argument("--no-enum", action="store_true", help="跳过子域枚举")
    parser.add_argument("--no-axfr", action="store_true", help="跳过区域传送尝试")
    parser.add_argument("-T", "--timeout", type=float, default=3.0, help="单次查询超时秒数（默认 3）")
    args = parser.parse_args()

    domain = args.domain.rstrip(".").lower()   # DNS 名大小写不敏感，统一小写展示
    if args.port is not None:
        if not args.resolver:
            print("[!] --port 需要配合 --resolver 使用", file=sys.stderr)
            return 1
        if not (1 <= args.port <= 65535):
            print("[!] --port 需在 1-65535 之间", file=sys.stderr)
            return 1
    port = args.port if args.port is not None else 53

    words = BUILTIN_WORDLIST
    if args.wordlist:
        with open(args.wordlist, encoding="utf-8") as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]

    resolver = make_resolver(args.resolver, port, args.timeout)
    where = f"{args.resolver}:{port}" if args.resolver else "系统解析器"
    print(f"[*] 目标 {domain}  解析器 {where}  线程 {args.threads}")

    apex = collect_apex(resolver, domain)
    print(f"\n[NS] 名称服务器（{len(apex['NS'])} 条）")
    for v in apex["NS"] or ["（无）"]:
        print(f"  {v}")

    if not args.no_enum:
        print(f"\n[SUB] 子域枚举（字典 {len(words)} 条，查 A/CNAME）")
        t0 = time.perf_counter()
        local = threading.local()              # 每线程一个解析器，避免共享状态

        def worker(sub):
            r = getattr(local, "r", None)
            if r is None:
                r = local.r = make_resolver(args.resolver, port, args.timeout)
            return probe_subdomain(r, f"{sub}.{domain}")

        hits = []
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            for fut in as_completed([pool.submit(worker, w) for w in words]):
                res = fut.result()
                if res:
                    hits.append(res)
        hits.sort()
        for name, rtype, value in hits:
            print(f"  {name:<28} {rtype:<6} {value}")
        print(f"  命中 {len(hits)}/{len(words)}，耗时 {time.perf_counter() - t0:.2f}s")
        if TIMEOUTS["n"]:
            print(f"  ⚠️ 期间 {TIMEOUTS['n']} 次查询超时——超时≠不存在，结果可能不完整")

    print(f"\n[MX] 邮件路由")
    for v in apex["MX"] or ["（无）"]:
        print(f"  {v}")
    print(f"\n[TXT] 文本记录")
    for v in apex["TXT"] or ["（无）"]:
        print(f"  {v}")

    if not args.no_axfr:
        servers = [args.resolver] if args.resolver else resolve_ns_ips(resolver, domain)
        if not servers:
            print("\n[AXFR] 无法确定 NS 地址，跳过")
        else:
            for target in servers:              # 挨个试：传送常只开在个别 NS 上
                print(f"\n[AXFR] 区域传送尝试 @ {target}:{port}")
                rows, err = try_axfr(target, domain, port, args.timeout)
                if rows is None:
                    print(f"  ❌ 被拒绝或失败：{err}（真实环境里这是常态）")
                    continue
                print(f"  ✅ 传送成功：{len(rows)} 条记录")
                for fqdn, ttl, rtype, rtext in rows:
                    print(f"  {fqdn:<28} {ttl:>6} IN {rtype:<6} {rtext}")
                break
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
