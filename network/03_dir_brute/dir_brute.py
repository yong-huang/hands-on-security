#!/usr/bin/env python3
"""03 · Web 目录爆破器（mini-dirsearch）

用法:
    python3 dir_brute.py <目标URL> [-w 字典] [-t 线程数] [-s 状态码] [-r] [--no-filter]
示例:
    python3 dir_brute.py http://127.0.0.1:8010 -r        # 打本实验靶站（默认读 configs/wordlist.txt）
    python3 dir_brute.py http://127.0.0.1:8010 --no-filter   # 关掉降噪，观察误报

能力: 字典驱动并发探测、状态码白名单、软 404 基线降噪、递归探测一层。
只依赖 requests；仅用于本地靶场与已授权目标。
"""
import argparse
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

import requests

DEFAULT_WORDLIST = Path(__file__).parent / "configs" / "wordlist.txt"
DEFAULT_STATUS = "200,204,301,302,307,401,403,405"
DIR_STATUS = {301, 302, 307, 308}                 # 目录重定向的常见状态码


def load_words(path):
    """读字典：忽略空行与 # 注释行。"""
    with open(path, encoding="utf-8") as f:
        words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
    if not words:
        sys.exit(f"[!] 字典 {path} 里没有可用词条")
    return words


class Http:
    """每线程一条 requests.Session（复用连接）；不共享状态。"""

    def __init__(self, timeout):
        self.timeout = timeout
        self.local = threading.local()

    def session(self):
        s = getattr(self.local, "s", None)
        if s is None:
            s = self.local.s = requests.Session()
            s.headers["User-Agent"] = "hosec-dir-brute/1.0 (lab; authorized testing only)"
        return s

    def get(self, url):
        """GET 且不跟随重定向——要看 301/302 的 Location 才知道是不是目录。出错返回 None。"""
        try:
            return self.session().get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None


def soft404_baseline(http, base, tol):
    """随机路径采样三次，识别软 404（未知路径也返回 200 的服务器）。

    返回 (基线 或 None, 目标是否可达, 备注)：基线 = (状态码, 中心长度, 窗口半宽)。
    长度波动不超过 tol 用窄窗口；动态页面波动大时自动加宽窗口兜底——
    放弃过滤会让所有软 404 变成误报。
    """
    sigs = []
    for _ in range(3):
        r = http.get(f"{base}/{uuid.uuid4().hex[:10]}")
        if r is None:
            return None, False, ""
        sigs.append((r.status_code, len(r.content)))
    sts = {s for s, _ in sigs}
    lens = [l for _, l in sigs]
    if len(sts) != 1:
        return None, True, ""
    lo, hi = min(lens), max(lens)
    center = (lo + hi) // 2
    if hi - lo <= tol:
        return (sts.pop(), center, tol), True, ""
    return (sts.pop(), center, (hi - lo) + tol), True, f"采样长度波动 {lo}~{hi}B，窗口自动加宽"


def hits_soft404(r, baseline):
    """响应是否撞上软 404 基线：状态码相同且长度落在窗口内 → 视为误报丢弃。"""
    if baseline is None:
        return False
    return r.status_code == baseline[0] and abs(len(r.content) - baseline[1]) <= baseline[2]


def scan(http, pool, words, base, whitelist, baseline, prefix=""):
    """并发扫一批词：命中实时打印，返回 (命中列表, 探测数)。"""
    hits = []

    def work(word):
        r = http.get(f"{base}/{quote(word)}")   # 含空格/特殊字符的词先编码
        if r is None or r.status_code not in whitelist:
            return None
        if hits_soft404(r, baseline):
            return None
        return word, r

    for fut in as_completed([pool.submit(work, w) for w in words]):
        item = fut.result()
        if not item:
            continue
        word, r = item
        name = f"{prefix}{word}"
        loc = r.headers.get("Location", "")
        detail = f" → {loc}" if loc else f" ({len(r.content)}B)"
        print(f"[+] /{name:<26} {r.status_code}{detail}", flush=True)
        hits.append((name, r.status_code))
    return hits, len(words)


def is_dir_hit(name, status):
    """目录判定：重定向状态码，或 200 且末段没有扩展名（点号）。"""
    if status in DIR_STATUS:
        return True
    return status == 200 and "." not in name.rsplit("/", 1)[-1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Web 目录爆破器：并发探测 + 状态码白名单 + 软 404 降噪 + 递归一层（仅限本地/授权目标）",
        epilog="示例: python3 dir_brute.py http://127.0.0.1:8010 -r")
    parser.add_argument("target", help="目标基址，如 http://127.0.0.1:8010")
    parser.add_argument("-w", "--wordlist", default=str(DEFAULT_WORDLIST),
                        help="字典文件（默认 configs/wordlist.txt，每行一个，# 开头为注释）")
    parser.add_argument("-t", "--threads", type=int, default=20, help="并发线程数（默认 20）")
    parser.add_argument("-s", "--status", default=DEFAULT_STATUS,
                        help=f"状态码白名单，逗号分隔（默认 {DEFAULT_STATUS}）")
    parser.add_argument("-r", "--recurse", action="store_true", help="对目录命中递归探测一层")
    parser.add_argument("--tol", type=int, default=10,
                        help="软 404 长度过滤窗口 ±N 字节（默认 10，动态页面可放宽）")
    parser.add_argument("--no-filter", action="store_true",
                        help="关闭软 404 基线过滤（观察误报用）")
    parser.add_argument("-T", "--timeout", type=float, default=3.0, help="单请求超时秒数（默认 3）")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    words = load_words(args.wordlist)
    whitelist = {int(x) for x in args.status.split(",") if x.strip()}
    http = Http(args.timeout)

    print(f"[*] 目标 {base}  字典 {len(words)} 条  线程 {args.threads}"
          f"  递归 {'1 层' if args.recurse else '关'}", flush=True)

    baseline = None
    if args.no_filter:
        print("[*] --no-filter：软 404 基线过滤关闭，未知路径也会被当成命中", flush=True)
    else:
        baseline, reachable, note = soft404_baseline(http, base, args.tol)
        if not reachable:
            print(f"[!] 无法连接目标 {base}（超时或拒绝连接）", file=sys.stderr)
            return 1
        if baseline and baseline[0] in whitelist:
            if note:
                print(f"[*] 软 404 基线（动态兜底）：随机路径 → {baseline[0]}，"
                      f"长度 {baseline[1]}B ±{baseline[2]}B（{note}）", flush=True)
            else:
                print(f"[*] 软 404 基线：随机路径 → {baseline[0]}，长度 {baseline[1]}B"
                      f"（同状态且长度 ±{args.tol}B 的响应将被丢弃）", flush=True)
        else:
            print("[*] 未发现可用软 404 基线（未知路径不在白名单或采样不稳定），按白名单直判", flush=True)

    t0 = time.perf_counter()
    probes = 0
    hits = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        top, n = scan(http, pool, words, base, whitelist, baseline)
        hits += top
        probes += n
        if args.recurse:
            for name, status in sorted(top):
                if not is_dir_hit(name, status):
                    continue
                print(f"[↻] 递归 /{name}/（{status} 判定为目录）", flush=True)
                sub, n = scan(http, pool, words, f"{base}/{name}", whitelist, baseline,
                              prefix=f"{name}/")
                hits += sub
                probes += n
    print(f"[=] 完成：{len(hits)} 个命中 / 探测 {probes} 个 URL，"
          f"耗时 {time.perf_counter() - t0:.2f}s", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
