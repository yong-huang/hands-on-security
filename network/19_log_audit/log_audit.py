#!/usr/bin/env python3
"""19 · 日志审计与爆破检测器 —— 合成日志 / 滑动窗口 / 规则引擎 / Markdown 报告

用法:
    python3 log_audit.py gen [--outdir artifacts]        # 合成 1000 条日志（含植入攻击）
    python3 log_audit.py audit --auth F --access F [--report R.md]
    python3 log_audit.py stats --access F                # Top10 来源 IP（stdout 纯文本）
    python3 log_audit.py probe                           # 对 DVWA 发真实攻击请求（供日志检出）

支持三种日志行：ssh 的 auth.log、Apache combined 格式、PHP 内置服务器
（Docker 容器日志）格式——按行自动识别。所有分析都在本机进行。
"""
import argparse
import random
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import requests

ART = Path(__file__).parent / "artifacts"
BASE = "http://127.0.0.1:8612"
SUSPECT = "203.0.113.66"
MILD = "198.51.100.23"
SCANNER = "192.0.2.44"
SCANNER_RE = re.compile(r"(sqlmap|gobuster|nikto|nmap|masscan|dirb|wfuzz|hydra)", re.I)
SQLI_RE = re.compile(r"(union\b.*select|\bor\b\+*%3d*\+*1|%27.*(?:or|union)|information_schema|sleep%28)", re.I)
TRAV_RE = re.compile(r"(\.\./|\.\.%2f|%2e%2e)", re.I)
XSS_RE = re.compile(r"(%3cscript|<script)", re.I)


def parse_line(line):
    """→ {'kind','ip','time','uri'|'event'}；不认识的返回 None。"""
    m = re.match(r"^(\w{3}\s+\d+\s+[\d:]+) \S+ sshd\[\d+\]: "
                 r"(Failed|Accepted) password for (?:invalid user )?(\S+) from ([\d.]+) port", line)
    if m:
        return {"kind": "auth", "time": m.group(1), "event": m.group(2), "ip": m.group(4)}
    m = re.match(r"^([\d.]+) - - \[([^\]]+)\] \"(\w+) (\S+)", line)
    if m:
        ua = re.search(r"\"([^\"]*)\"$", line.strip())
        return {"kind": "access", "time": m.group(2), "ip": m.group(1),
                "uri": m.group(4), "ua": ua.group(1) if ua else ""}
    m = re.match(r"^\[\d+\] \[([^\]]+)\] ([\d.]+):\d+ \[\d+\]: (\w+) (\S+)", line)
    if m:
        return {"kind": "web", "time": m.group(1), "ip": m.group(2),
                "uri": m.group(4), "ua": ""}
    return None


def read_events(path):
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        e = parse_line(line)
        if e:
            out.append(e)
    return out


def max_in_window(times, window=60):
    """时间戳字符串按同一天内排序后，任意 window 秒内最多的条数。"""
    ts = sorted(datetime.strptime(t, "%b %d %H:%M:%S") for t in times)
    best, i = 0, 0
    for j in range(len(ts)):
        while (ts[j] - ts[i]).total_seconds() >= window:
            i += 1
        best = max(best, j - i + 1)
    return best


def apply_rules(events, min_fails=30, window=60):
    findings = []
    fails = defaultdict(list)
    oks = Counter()
    for e in events:
        if e["kind"] == "auth":
            if e["event"] == "Failed":
                fails[e["ip"]].append(e["time"])
            else:
                oks[e["ip"]] += 1
    for ip, times in fails.items():
        n = len(times)
        top = max_in_window(times, window)
        if top >= min_fails:
            findings.append((ip, "R1", f"爆破检测：{window} 秒窗口内失败 {top} 次（阈值 {min_fails}）"))
        if n >= 10 and oks[ip]:
            findings.append((ip, "R6", f"爆破后成功登录：失败 {n} 次后出现 Accepted"))
    seen_ua, seen_sqli = set(), defaultdict(list)
    for e in events:
        if e["kind"] not in ("access", "web"):
            continue
        ua = e.get("ua", "")
        if SCANNER_RE.search(ua) and e["ip"] not in seen_ua:
            seen_ua.add(e["ip"])
            findings.append((e["ip"], "R2", f"扫描器 UA：{ua}（例：GET {e['uri']}）"))
        if SQLI_RE.search(e["uri"]):
            seen_sqli[e["ip"]].append(e["uri"])
    for ip, uris in seen_sqli.items():
        findings.append((ip, "R3", f"SQL 注入特征：{len(uris)} 条请求命中（例：GET {uris[0]}）"))
    for e in events:
        if e["kind"] in ("access", "web"):
            if TRAV_RE.search(e["uri"]):
                findings.append((e["ip"], "R4", f"路径穿越特征：GET {e['uri']}"))
                break
    for e in events:
        if e["kind"] in ("access", "web"):
            if XSS_RE.search(e["uri"]):
                findings.append((e["ip"], "R5", f"XSS 特征：GET {e['uri']}"))
                break
    findings.sort(key=lambda f: (f[0], f[1]))
    return findings


def cmd_gen(a):
    random.seed(19)
    ART.mkdir(exist_ok=True)
    auth, access = [], []

    def t(mm, ss):
        return f"May  1 03:{mm:02d}:{ss:02d}"

    pid = 2000
    for i in range(50):                                   # 植入①：50 次失败集中在 1 分钟
        pid += 1
        auth.append(f"{t(5, i)} labhost sshd[{pid}]: Failed password for admin from {SUSPECT} port {40000 + i} ssh2")
    auth.append(f"{t(6, 11)} labhost sshd[{pid}] : Accepted password for admin from {SUSPECT} port 40512 ssh2"
                .replace("] :", "]:"))
    for i in range(8):                                    # 负对照：8 次散落失败（低于阈值）
        auth.append(f"{t(10 + i * 2, 30)} labhost sshd[{4000 + i}]: Failed password for admin from {MILD} port {41000 + i} ssh2")
    normal_ips = ["198.51.100.10", "192.0.2.10", "198.51.100.77", "203.0.113.9"]
    while len(auth) < 600:                                # 背景流量填满 600 行
        ip = random.choice(normal_ips)
        kind = "Failed" if random.random() < 0.05 else "Accepted"
        auth.append(f"{t(random.randint(0, 4), random.randint(0, 59))} labhost sshd[{random.randint(5000, 5999)}]: "
                    f"{kind} password for admin from {ip} port {random.randint(42000, 60999)} ssh2")
    auth.sort(key=lambda l: l[5:20])

    access_counts = {"198.51.100.10": 110, "198.51.100.23": 88, "192.0.2.10": 61, "192.0.2.44": 46,
                     "198.51.100.77": 33, "203.0.113.9": 21, "192.0.2.99": 14, "198.51.100.50": 11,
                     "203.0.113.66": 9, "192.0.2.77": 7}
    normal_uris = ["/", "/index.php", "/login.php", "/about.php", "/images/logo.png",
                   "/vulnerabilities/xss_r/?name=John", "/vulnerabilities/setup.php"]
    sqli_uris = ["/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2Cpassword+FROM+users--&Submit=Submit",
                 "/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit",
                 "/vulnerabilities/sqli_blind/?id=1%27+AND+SLEEP%285%29--&Submit=Submit",
                 "/vulnerabilities/sqli/?id=1+union+select+1%2C2--&Submit=Submit"]
    for ip, n in access_counts.items():
        for i in range(n):
            sec = random.randint(0, 3599)
            ts = f"01/May/2026:03:{sec // 60:02d}:{sec % 60:02d} +0800"
            if ip == SUSPECT:
                uri, status, ua = sqli_uris[i % len(sqli_uris)], 200, "sqlmap/1.7#stable"
            elif ip == SCANNER:
                uri, status, ua = f"/{random.choice(['admin', 'backup', '.git/config', 'uploads'])}/", 404, "gobuster/3.6"
            else:
                uri, status, ua = random.choice(normal_uris), 200, \
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            access.append(f'{ip} - - [{ts}] "GET {uri} HTTP/1.1" {status} {random.randint(180, 4096)} "-" "{ua}"')
    access.sort(key=lambda l: l.split("[")[1])

    (ART / "auth-synth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")
    (ART / "access-synth.log").write_text("\n".join(access) + "\n", encoding="utf-8")
    print(f"[gen] 合成日志 1000 条：auth {len(auth)} + access {len(access)}")
    print(f"[gen] 植入：{SUSPECT} 一分钟内 50 次失败 + sqlmap/注入 URI；负对照：{MILD} 8 次散落失败")
    return 0


def cmd_stats(a):
    events = [e for e in read_events(a.access) if e["kind"] in ("access", "web")]
    counter = Counter(e["ip"] for e in events)
    for ip, n in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:a.top]:
        print(f"{n} {ip}")
    return 0


def cmd_audit(a):
    events = []
    files = []
    if a.auth:
        events += read_events(a.auth)
        files.append(f"{Path(a.auth).name}（{sum(1 for _ in Path(a.auth).read_text().splitlines())} 行）")
    if a.access:
        events += read_events(a.access)
        files.append(f"{Path(a.access).name}（{sum(1 for _ in Path(a.access).read_text().splitlines())} 行）")
    print(f"[audit] 输入：{' + '.join(files)}")
    findings = apply_rules(events, a.min_fails, a.window)
    print(f"[audit] 规则命中：")
    for ip, rid, msg in findings:
        print(f"  [{rid}] {msg}（来源 {ip}）")
    by_ip = Counter(ip for ip, _, _ in findings)
    suspects = "、".join(f"{ip}（{n} 条）" for ip, n in
                        sorted(by_ip.items(), key=lambda kv: (-kv[1], kv[0])))
    print(f"[audit] 共 {len(findings)} 条规则命中；可疑 IP：{suspects}")
    if a.report:
        write_report(a, events, findings, by_ip)
        print(f"[audit] Markdown 审计报告 → {a.report}")
    return 0


def write_report(a, events, findings, by_ip):
    counter = Counter(e["ip"] for e in events if e["kind"] in ("access", "web"))
    lines = ["# 日志审计报告（自动生成）", "",
             f"> 数据窗口：2026-05-01 03:00-04:00（合成）· 输入："
             f"{Path(a.auth).name if a.auth else '-'} + {Path(a.access).name if a.access else '-'} · "
             f"工具：log_audit.py", "", "## 1. 结论摘要", ""]
    top = sorted(by_ip.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    lines.append(f"共检出 **{len(findings)} 条规则命中**，涉及 {len(by_ip)} 个可疑来源；"
                 f"最活跃可疑 IP：{top[0][0]}（{top[0][1]} 条规则）。" if top else "未检出可疑行为。")
    lines += ["", "## 2. 规则命中", ""]
    for ip, rid, msg in findings:
        lines.append(f"- **[{rid}]** {msg}（来源 `{ip}`）")
    lines += ["", "## 3. Top 10 来源 IP（按 HTTP 请求数）", "",
              "| 排名 | IP | 请求数 |", "|:---:|:---|:---:|"]
    for i, (ip, n) in enumerate(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:10], 1):
        lines.append(f"| {i} | {ip} | {n} |")
    lines += ["", "## 4. 建议动作", "",
              f"- 对最活跃可疑 IP（{top[0][0] if top else '-'}）临时封禁并复核账号口令强度；",
              "- 检查同期是否存在成功的登录（R6 命中意味着口令可能已泄露）；",
              "- 针对注入类 URI 特征在 WAF/IDS 增加规则（实验 20-21 将落地）。"]
    Path(a.report).write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_probe(a):
    probes = [
        ("sqli-union", "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2Cpassword+FROM+users--&Submit=Submit"),
        ("sqli-or", "/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit"),
        ("lfi", "/vulnerabilities/fi/?page=..%2F..%2F..%2Fetc%2Fpasswd"),
        ("xss", "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ]
    for name, path in probes:
        requests.get(f"{BASE}{path}", timeout=8)
        print(f"[probe] 已发出 {name}：GET {path}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="日志审计与爆破检测（本机）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p0 = sub.add_parser("gen")
    p0.set_defaults(func=cmd_gen)
    p1 = sub.add_parser("stats")
    p1.add_argument("--access", required=True)
    p1.add_argument("--top", type=int, default=10)
    p1.set_defaults(func=cmd_stats)
    p2 = sub.add_parser("audit")
    p2.add_argument("--auth", default=None)
    p2.add_argument("--access", default=None)
    p2.add_argument("--report", default=None)
    p2.add_argument("--min-fails", type=int, default=30)
    p2.add_argument("--window", type=int, default=60)
    p2.set_defaults(func=cmd_audit)
    p3 = sub.add_parser("probe")
    p3.set_defaults(func=cmd_probe)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
