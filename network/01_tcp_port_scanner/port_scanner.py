#!/usr/bin/env python3
"""01 · 多线程 TCP 端口扫描器

用法:
    python3 port_scanner.py <目标> [-p 端口范围] [-t 线程数] [-T 超时] [--rate 速率]

示例:
    python3 port_scanner.py 127.0.0.1 -p 1-1000 -t 100     # 最常用的验收命令
    python3 port_scanner.py 127.0.0.1 -p 22,80,8000-8010   # 逗号与区间混写
    python3 port_scanner.py 127.0.0.1 -p 1-100 --rate 50   # 全局限速 50 次/秒

原理: TCP connect 扫描 —— 对每个端口发起完整的三次握手 connect()，
握手成功=开放；被拒绝=关闭；超时=被过滤。只依赖 Python 标准库。
"""
import argparse
import errno
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# 这些端口的服务不会主动打招呼，需要客户端先发 HTTP 请求才回响应（用于 banner 抓取）。
# 注意不含 443/8443：HTTPS 服务要等 TLS ClientHello，发明文 HEAD 只会被当成畸形握手。
HTTP_PORTS = {80, 3000, 5000, 7000, 8000, 8001, 8080, 8081, 9000}
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n"   # Host 用目标真实地址填充
BANNER_LIMIT = 80          # banner 最长打印字符数，防日志被超长响应撑爆


def parse_ports(spec: str) -> list:
    """解析 "1-1000" / "22,80,443" / "22,8000-8010" 这类端口表达式。"""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
        else:
            lo = hi = int(part)
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"端口范围非法: {part}（合法区间 1-65535 且左≤右）")
        ports.update(range(lo, hi + 1))
    if not ports:
        raise ValueError("端口列表为空")
    return sorted(ports)


class RateLimiter:
    """全局限速器：按固定最小间隔放行探测，多线程共用一个"发号机"。"""

    def __init__(self, rate: int):
        self.interval = 1.0 / rate if rate else 0.0
        self.lock = threading.Lock()
        self.next_time = time.monotonic()

    def wait(self) -> None:
        if not self.interval:
            return
        with self.lock:                        # 取号本身要互斥，否则线程会同时出发
            now = time.monotonic()
            self.next_time = max(self.next_time, now)
            delay = self.next_time - now
            self.next_time += self.interval
        if delay > 0:
            time.sleep(delay)


def grab_banner(sock: socket.socket, port: int, timeout: float, ip: str) -> str:
    """被动收 banner（只取首个 TCP 段）；HTTP 类端口补发一次 HEAD 主动要 banner。"""
    sock.settimeout(timeout)
    data = b""
    try:
        data = sock.recv(1024)                 # SSH/FTP 等协议连上先说话
    except (socket.timeout, OSError):
        pass
    if not data and port in HTTP_PORTS:        # HTTP 服务要等请求，主动问一句
        try:
            sock.sendall(HTTP_PROBE % ip.encode())   # Host 用真实目标，虚拟主机才回对站点
            data = sock.recv(1024)
        except OSError:
            pass
    if not data:
        return "-"
    lines = [l.strip() for l in data.decode("utf-8", errors="replace").splitlines() if l.strip()]
    first = lines[0] if lines else "-"
    server = next((l for l in lines if l.lower().startswith("server:")), None)
    banner = f"{first} | {server}" if first.startswith("HTTP/") and server else (server or first)
    return banner[:BANNER_LIMIT]


def scan_one(ip: str, port: int, timeout: float, limiter: RateLimiter):
    """探测单个端口：返回 (port, banner) 或 None（关闭/过滤）。"""
    limiter.wait()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # 只报 open：RST=closed、超时/不可达=filtered，都不进结果集
            if s.connect_ex((ip, port)) != 0:
                return None
            return port, grab_banner(s, port, timeout, ip)
    except OSError as e:
        if e.errno in (errno.EMFILE, errno.ENFILE):
            raise                              # 文件描述符耗尽必须暴露：否则「端口全关」是假象
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="多线程 TCP connect 端口扫描器（仅限本地/授权目标）",
        epilog="示例: python3 port_scanner.py 127.0.0.1 -p 1-1000 -t 100")
    parser.add_argument("target", help="目标 IP 或主机名")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="端口表达式: 1-1000 / 22,80,443 / 22,8000-8010（默认 1-1024）")
    parser.add_argument("-t", "--threads", type=int, default=100, help="并发线程数（默认 100）")
    parser.add_argument("-T", "--timeout", type=float, default=0.5, help="单端口超时秒数（默认 0.5）")
    parser.add_argument("--rate", type=int, default=0, help="全局限速（次/秒，0=不限速）")
    args = parser.parse_args()
    if args.threads < 1:
        parser.error("线程数必须 ≥ 1")
    if args.timeout <= 0:
        parser.error("超时必须 > 0")

    try:
        ip = socket.gethostbyname(args.target)   # 域名先解析成 IP，扫描只面向 IP
    except socket.gaierror:
        print(f"[!] 无法解析目标: {args.target}", file=sys.stderr)
        return 1
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    rate_info = f"  限速 {args.rate}/s" if args.rate else ""
    print(f"[*] 目标 {args.target} ({ip})  端口 {len(ports)} 个  线程 {args.threads}  "
          f"超时 {args.timeout}s{rate_info}")

    limiter = RateLimiter(args.rate)
    lock = threading.Lock()                      # 保护 print 与 results 的并发写入
    results = []
    t0 = time.perf_counter()
    pool = ThreadPoolExecutor(max_workers=args.threads)
    try:
        futures = [pool.submit(scan_one, ip, p, args.timeout, limiter) for p in ports]
        for fut in as_completed(futures):        # 谁先扫完谁先报，结果实时可见
            r = fut.result()
            if r:
                with lock:
                    results.append(r)
                    print(f"[+] {r[0]}/tcp open  {r[1]}")
    except OSError as e:
        if e.errno in (errno.EMFILE, errno.ENFILE):
            print("[!] 文件描述符不足：降低 -t 线程数，或先 ulimit -n 4096", file=sys.stderr)
            return 1
        raise
    finally:
        pool.shutdown(wait=False, cancel_futures=True)   # 中断时不等待未跑完的任务
    elapsed = time.perf_counter() - t0

    results.sort()
    print(f"[=] 完成：{len(results)} 个开放端口 / {len(ports)} 个探测，耗时 {elapsed:.2f}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
