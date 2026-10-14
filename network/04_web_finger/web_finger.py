#!/usr/bin/env python3
"""04 · Web 指纹识别器

用法:
    python3 web_finger.py <目标URL> [-r 规则文件] [-T 超时]
示例:
    python3 web_finger.py http://127.0.0.1:8023          # 识别本实验的仿真 PHP 站
    python3 web_finger.py http://127.0.0.1:8022 -r my.json   # 换一套规则

三个信号源: 响应头 / HTML 特征 / favicon md5；规则为 JSON（见 configs/）。
只依赖 requests；仅用于本地靶场与已授权目标。
"""
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

import requests

DEFAULT_RULES = Path(__file__).parent / "configs" / "fingerprint_rules.json"
UA = "hosec-web-finger/1.0 (lab; authorized testing only)"
INTERESTING_HEADERS = ["Server", "X-Powered-By", "X-Generator", "Set-Cookie", "Via"]
CATEGORY_CN = {"server": "服务器", "language": "语言", "framework": "框架", "cms": "CMS"}
CATEGORY_ORDER = ["server", "language", "framework", "cms"]


def collect(target, timeout):
    """抓取首页与 favicon，返回信号字典：响应头、HTML 文本、favicon md5。"""
    r = requests.get(target, timeout=timeout, headers={"User-Agent": UA})
    sig = {
        "status": r.status_code,
        "headers": {h: r.headers[h] for h in INTERESTING_HEADERS if h in r.headers},
        "body": r.text[:200_000],          # 只看前 200KB，特征都在头部区域
        "favicon_md5": None,
        "favicon_len": 0,
        "favicon_status": None,
    }
    fr = requests.get(urljoin(target + "/", "favicon.ico"),
                      timeout=timeout, headers={"User-Agent": UA})
    sig["favicon_status"] = fr.status_code
    if fr.status_code == 200 and fr.content:
        sig["favicon_md5"] = hashlib.md5(fr.content).hexdigest()
        sig["favicon_len"] = len(fr.content)
    return sig


def rule_evidence(rule, sig):
    """检查一条规则：所有条件组都命中才返回证据文本，否则返回 None。"""
    m = rule["match"]
    evidence = []
    if "server_contains" in m:
        server = sig["headers"].get("Server", "")
        if not any(s in server for s in m["server_contains"]):
            return None
        evidence.append(f"Server: {server}")
    if "header_contains" in m:
        for hdr, subs in m["header_contains"].items():
            val = sig["headers"].get(hdr, "")
            if not any(s in val for s in subs):
                return None
            evidence.append(f"{hdr}: {val}")
    if "body_contains" in m:
        hit = next((s for s in m["body_contains"] if s in sig["body"]), None)
        if hit is None:
            return None
        evidence.append(f"HTML 含 {hit}")
    if "favicon_md5" in m:
        if sig["favicon_md5"] not in m["favicon_md5"]:
            return None
        evidence.append(f"favicon md5 {sig['favicon_md5']}")
    return "；".join(evidence)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Web 指纹识别器：响应头 + HTML 特征 + favicon hash（仅限本地/授权目标）",
        epilog="示例: python3 web_finger.py http://127.0.0.1:8023")
    parser.add_argument("target", help="目标基址，如 http://127.0.0.1:8023")
    parser.add_argument("-r", "--rules", default=str(DEFAULT_RULES),
                        help="规则文件（默认 configs/fingerprint_rules.json）")
    parser.add_argument("-T", "--timeout", type=float, default=5.0, help="请求超时秒数（默认 5）")
    args = parser.parse_args()

    with open(args.rules, encoding="utf-8") as f:
        rules = json.load(f)["rules"]
    target = args.target.rstrip("/")

    t0 = time.perf_counter()
    try:
        sig = collect(target, args.timeout)
    except requests.RequestException as e:
        print(f"[!] 无法访问目标 {target}：{type(e).__name__}", file=sys.stderr)
        return 1

    print(f"[*] 目标 {target}  状态 {sig['status']}  规则 {len(rules)} 条")
    for hdr, val in sig["headers"].items():
        print(f"[HEAD] {hdr}: {val}")
    if sig["favicon_md5"]:
        print(f"[FAV]  favicon.ico {sig['favicon_len']}B，md5 {sig['favicon_md5']}")
    else:
        print(f"[FAV]  favicon.ico 未提供（HTTP {sig['favicon_status']}）")

    hits = []
    for rule in rules:
        evidence = rule_evidence(rule, sig)
        if evidence:
            hits.append((rule, evidence))
    hits.sort(key=lambda h: (CATEGORY_ORDER.index(h[0]["category"]), h[0]["name"]))
    for rule, evidence in hits:
        cat = CATEGORY_CN[rule["category"]]
        print(f"[HIT] {cat} · {rule['name']}  证据：{evidence}")

    parts = []
    for cat in CATEGORY_ORDER:
        n = sum(1 for r, _ in hits if r["category"] == cat)
        if n:
            parts.append(f"{CATEGORY_CN[cat]} {n}")
    print(f"[=] 完成：命中 {len(hits)} 条规则（{' · '.join(parts) if parts else '无'}），"
          f"耗时 {time.perf_counter() - t0:.2f}s")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
