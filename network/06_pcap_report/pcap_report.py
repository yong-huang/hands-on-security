#!/usr/bin/env python3
"""06 · pcap 流量分析报告生成器

用法:
    python3 pcap_report.py make-sample artifacts/demo-login.pcap   # 合成演示 pcap（免 root）
    python3 pcap_report.py report artifacts/demo-login.pcap -o artifacts/report.md

能力：分析任意 pcap——协议分布、Top Talker、HTTP 明文明细、凭据提取、
Markdown 报告。只依赖 scapy；全程离线，不产生网络流量。
"""
import argparse
import json
import sys
import urllib.parse
from collections import Counter
from pathlib import Path

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw,
                       rdpcap, wrpcap)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.record import TLS

BASE_TIME = 1750000000.0                    # 样本 pcap 的固定起始时间（可复现）
REASONS = {200: "OK", 302: "Found", 401: "Unauthorized", 404: "Not Found"}
CRED_USER_KEYS = {"username", "user", "uname", "login", "email"}
CRED_PASS_KEYS = {"password", "passwd", "pass", "pwd"}


# ============================================================ 合成样本
def http_request(method, path, host, body=b""):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}",
             "User-Agent: Mozilla/5.0 (hosec-lab)", "Accept: */*"]
    if body:
        lines += ["Content-Type: application/x-www-form-urlencoded",
                  f"Content-Length: {len(body)}"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(status, body="", location=None):
    raw = body.encode()
    lines = [f"HTTP/1.1 {status} {REASONS.get(status, 'Unknown')}",
             "Server: nginx/1.24.0", "Content-Type: text/html; charset=utf-8",
             f"Content-Length: {len(raw)}"]
    if location:
        lines.append(f"Location: {location}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + raw


def tcp_frames(c, s, sport, dport, steps, t0):
    """生成一次 TCP 会话：三次握手 + 交替载荷 + 四次挥手。steps 为 [(方向, 载荷)]。"""
    frames, t = [], t0
    sc, ss = 1000, 9000

    def frame(frm, to, flags, seq, ack, load=b""):
        nonlocal t
        t += 0.012
        p = (Ether(src=frm["mac"], dst=to["mac"]) /
             IP(src=frm["ip"], dst=to["ip"]) /
             TCP(sport=sport if frm is c else dport,
                 dport=dport if frm is c else sport,
                 seq=seq, ack=ack, flags=flags, window=64240))
        if load:
            p = p / Raw(load)
        p.time = BASE_TIME + t
        frames.append(p)

    frame(c, s, "S", sc, 0)
    frame(s, c, "SA", ss, sc + 1)
    frame(c, s, "A", sc + 1, ss + 1)
    sc, ss = sc + 1, ss + 1
    for direction, load in steps:
        if direction == ">":
            frame(c, s, "PA", sc, ss, load)
            sc += len(load)
        else:
            frame(s, c, "PA", ss, sc, load)
            ss += len(load)
        frame(c if direction == ">" else s, s if direction == ">" else c, "A",
              sc if direction == ">" else ss, ss if direction == ">" else sc)
    frame(c, s, "FA", sc, ss)
    frame(s, c, "FA", ss, sc + 1)
    frame(c, s, "A", sc + 1, ss + 1)
    return frames


def build_sample(cfg):
    C, S, G, T = cfg["client"], cfg["server"], cfg["gateway"], cfg["tls_peer"]
    pkts, t = [], 0.10

    def put(p, dt):
        nonlocal t
        t += dt
        p.time = BASE_TIME + t
        pkts.append(p)

    put(Ether(src=C["mac"], dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, hwsrc=C["mac"], psrc=C["ip"], pdst=G["ip"]), 0.05)
    put(Ether(src=G["mac"], dst=C["mac"]) /
        ARP(op=2, hwsrc=G["mac"], psrc=G["ip"], hwdst=C["mac"], pdst=C["ip"]), 0.05)

    qd = DNSQR(qname=S["hostname"])
    put(Ether(src=C["mac"], dst=G["mac"]) / IP(src=C["ip"], dst="10.0.0.53") /
        UDP(sport=53123, dport=53) / DNS(id=0x1234, rd=1, qd=qd), 0.05)
    put(Ether(src=G["mac"], dst=C["mac"]) / IP(src="10.0.0.53", dst=C["ip"]) /
        UDP(sport=53, dport=53123) /
        DNS(id=0x1234, qr=1, aa=1, qd=qd,
            an=DNSRR(rrname=S["hostname"] + ".", ttl=300, rdata=S["ip"])), 0.05)

    steps = []
    for item in cfg["http"]:
        if item["method"] == "GET":
            steps.append((">", http_request("GET", item["path"], S["hostname"])))
        else:
            body = urllib.parse.urlencode(item["form"]).encode()
            steps.append((">", http_request("POST", item["path"], S["hostname"], body)))
        steps.append(("<", http_response(item["response"], item.get("response_body", ""),
                                        item.get("location"))))
    pkts += [p for p in tcp_frames(C, S, 49152, 80, steps, t)]
    t = pkts[-1].time - BASE_TIME + 0.05

    # 对照流量：一个 TLS 会话（只有 ClientHello，看不到任何明文内容）
    hello_body = (b"\x03\x03" + bytes(range(32)) + b"\x00" +
                  b"\x00\x02\x00\x2f" + b"\x01\x00")
    record = b"\x16\x03\x01" + (4 + len(hello_body)).to_bytes(2, "big") + \
        b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
    pkts += tcp_frames(C, T, 49200, 443, [(">", record)], t)
    t = pkts[-1].time - BASE_TIME + 0.05

    for i in range(2):
        put(Ether(src=C["mac"], dst=G["mac"]) /
            IP(src=C["ip"], dst=G["ip"]) / ICMP(id=0x55 + i, seq=i + 1), 0.02)
        put(Ether(src=G["mac"], dst=C["mac"]) /
            IP(src=G["ip"], dst=C["ip"]) / ICMP(id=0x55 + i, seq=i + 1, type=0), 0.02)
    pkts.sort(key=lambda p: p.time)
    return pkts


# ============================================================ 分析
def count_protocols(pkts):
    c = Counter(total=len(pkts))
    c["tcp"] = sum(1 for p in pkts if p.haslayer(TCP))
    c["udp"] = sum(1 for p in pkts if p.haslayer(UDP))
    c["icmp"] = sum(1 for p in pkts if p.haslayer(ICMP))
    c["arp"] = sum(1 for p in pkts if p.haslayer(ARP))
    c["dns"] = sum(1 for p in pkts if p.haslayer(DNS))
    c["http"] = sum(1 for p in pkts if p.haslayer(HTTPRequest) or p.haslayer(HTTPResponse))
    c["tls"] = sum(1 for p in pkts if p.haslayer(TLS))
    return c


def top_talkers(pkts, top=5):
    packets, bytes_ = Counter(), Counter()
    for p in pkts:
        if p.haslayer(IP):
            for ip in (p[IP].src, p[IP].dst):
                packets[ip] += 1
            bytes_[p[IP].src] += len(p)
            bytes_[p[IP].dst] += len(p)
    rows = [(ip, packets[ip], bytes_[ip]) for ip, _ in packets.most_common(top)]
    return rows


def http_transactions(pkts):
    """把 HTTPRequest / HTTPResponse 按出现顺序配对。"""
    rows = []
    for p in pkts:
        if p.haslayer(HTTPRequest):
            req = p[HTTPRequest]
            host = getattr(req, "Host", b"").decode("utf-8", "replace") or "-"
            rows.append({
                "time": float(p.time),
                "method": req.Method.decode("utf-8", "replace"),
                "url": f"{host}{req.Path.decode('utf-8', 'replace')}",
                "status": None, "src": p[IP].src if p.haslayer(IP) else "-",
            })
        elif p.haslayer(HTTPResponse) and rows:
            for row in reversed(rows):
                if row["status"] is None:
                    row["status"] = p[HTTPResponse].Status_Code.decode("utf-8", "replace")
                    break
    return rows


def extract_credentials(pkts):
    found = []
    for p in pkts:
        if not p.haslayer(HTTPRequest):
            continue
        req = p[HTTPRequest]
        if req.Method.decode("utf-8", "replace").upper() != "POST":
            continue
        body = bytes(p[Raw].load) if p.haslayer(Raw) else b""
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        user = next((v[0] for k, v in form.items() if k.lower() in CRED_USER_KEYS), "-")
        pwd = next((v[0] for k, v in form.items() if k.lower() in CRED_PASS_KEYS), "-")
        if user != "-" or pwd != "-":
            host = getattr(req, "Host", b"").decode("utf-8", "replace") or "-"
            found.append({
                "time": float(p.time),
                "user": user, "pwd": pwd,
                "url": f"http://{host}{req.Path.decode('utf-8', 'replace')}",
                "src": p[IP].src if p.haslayer(IP) else "-",
                "dst": p[IP].dst if p.haslayer(IP) else "-",
            })
    return found


def build_report(path, pkts, counts, talkers, http_rows, creds):
    span = float(pkts[-1].time - pkts[0].time) if len(pkts) > 1 else 0.0
    md = ["# pcap 流量分析报告", "",
          f"- 文件：`{path.name}`（{counts['total']} 个包，跨度 {span:.2f}s）", "",
          "## 协议分布", "", "| 协议 | 包数 |", "|:---|:---:|"]
    for name in ("tcp", "udp", "icmp", "arp", "dns", "http", "tls"):
        md.append(f"| {name.upper()} | {counts[name]} |")
    md += ["", "> 注：HTTP/TLS/DNS 叠加在 TCP/UDP 之上统计，与 TCP 行并不互斥。",
           "", "## Top Talker（按包数）", "", "| IP | 包数 | 字节 |", "|:---|---:|---:|"]
    for ip, n, b in talkers:
        md.append(f"| {ip} | {n} | {b} |")
    md += ["", "## HTTP 明文事务", "", "| 方法 | URL | 状态 | 来源 |", "|:---|:---|:---|:---|"]
    for row in http_rows:
        md.append(f"| {row['method']} | {row['url']} | {row['status'] or '-'} | {row['src']} |")
    md += ["", "## 明文凭据（警报）", ""]
    if creds:
        md += ["| 用户名 | 口令 | 目标 | 来源 |", "|:---|:---|:---|:---|"]
        for c in creds:
            md.append(f"| {c['user']} | {c['pwd']} | {c['url']} | {c['src']} |")
        md += ["", f"共 {len(creds)} 条；HTTP 明文传输，嗅探者可直接读到。"]
    else:
        md.append("未发现明文凭据。")
    md += ["", "## 结论与建议", "",
           "1. 明文 HTTP 登录把账号口令暴露在同网段任何一个抓包者面前——上线前强制 HTTPS。",
           "2. TLS 会话（本 pcap 中的 443 流量）看不到任何内容，这正是要推广的理由。",
           "3. 抓包分析是攻防两用的基本功：蓝队用它回溯事件，红队用它嗅探明文。"]
    return "\n".join(md) + "\n"


# ============================================================ CLI
def cmd_make_sample(args):
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    pkts = build_sample(cfg)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(args.out, pkts)
    print(f"[=] 样本 pcap 已生成：{args.out}（{len(pkts)} 个包，回放一次明文登录会话）")
    return 0


def cmd_report(args):
    pkts = rdpcap(args.pcap)
    if not pkts:
        print("[!] pcap 为空", file=sys.stderr)
        return 1
    counts = count_protocols(pkts)
    talkers = top_talkers(pkts)
    http_rows = http_transactions(pkts)
    creds = extract_credentials(pkts)

    span = float(pkts[-1].time - pkts[0].time)
    print(f"[*] 读取 {args.pcap}：{counts['total']} 个包，跨度 {span:.2f}s")
    print("[STAT] " + " ".join(f"{k}={counts[k]}" for k in
                               ("total", "tcp", "udp", "icmp", "arp", "dns", "http", "tls")))
    for ip, n, b in talkers:
        print(f"[TALK] {ip:<16} {n:>4} 个包 {b:>8} 字节")
    for row in http_rows:
        print(f"[HTTP] {row['method']:<5} {row['url']:<40} → {row['status'] or '-'}")
    for c in creds:
        print(f"[ALERT] 明文凭据：{c['user']} / {c['pwd']}（POST {c['url']}，"
              f"{c['src']} → {c['dst']}）")
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(build_report(Path(args.pcap), pkts, counts, talkers,
                                               http_rows, creds), encoding="utf-8")
        print(f"[=] 报告已生成：{args.out}（明文凭据 {len(creds)} 条）")
    return 0


def main():
    parser = argparse.ArgumentParser(description="pcap 流量分析报告生成器（离线分析）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("make-sample", help="合成演示 pcap（回放一次明文登录会话）")
    p1.add_argument("out")
    p1.add_argument("--config", default=str(Path(__file__).parent / "configs" / "demo_session.json"))
    p1.set_defaults(func=cmd_make_sample)

    p2 = sub.add_parser("report", help="分析 pcap 并输出 Markdown 报告")
    p2.add_argument("pcap")
    p2.add_argument("-o", "--out", help="Markdown 报告输出路径")
    p2.set_defaults(func=cmd_report)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
