#!/usr/bin/env python3
"""20 · 生成三段测试 pcap（离线构造，无需 root）：
     scan-syn.pcap —— 198.51.100.77 对 192.0.2.10 的 1-100 端口 SYN 扫描
     sqli-union.pcap —— 一条带 union select 的 HTTP 请求（含三次握手）
     benign.pcap —— 一条正常 HTTP 请求（负对照：不应告警）
"""
import argparse
from datetime import datetime
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SCANNER, TARGET = "198.51.100.77", "192.0.2.10"
CLIENT, SERVER = "198.51.100.88", "192.0.2.10"
MAC_S, MAC_T = "02:00:00:00:00:77", "02:00:00:00:00:10"
MAC_C, MAC_SV = "02:00:00:00:00:88", "02:00:00:00:00:10"


def eth(src, dst):
    return Ether(src=src, dst=dst)


def scan_pcap(base):
    pkts = []
    for i, port in enumerate(range(1, 101)):
        t = base + i * 0.02
        sport = 40000 + i
        syn = eth(MAC_S, MAC_T) / IP(src=SCANNER, dst=TARGET) / \
            TCP(sport=sport, dport=port, flags="S", seq=1000 + i)
        syn.time = t
        flags = "SA" if port == 80 else "RA"          # 80 假装开着，其余拒绝
        rep = eth(MAC_T, MAC_S) / IP(src=TARGET, dst=SCANNER) / \
            TCP(sport=port, dport=sport, flags=flags, seq=0 if flags == "RA" else 5000,
                ack=1001 + i if flags == "RA" else 1001 + i)
        rep.time = t + 0.001
        pkts.append(syn)
        pkts.append(rep)
    return pkts


def http_session(base, uri, ua, sport):
    seq_c, seq_s = 50000, 900000
    s2c = eth(MAC_C, MAC_SV) / IP(src=CLIENT, dst=SERVER)
    c2s = eth(MAC_SV, MAC_C) / IP(src=SERVER, dst=CLIENT)
    pkts = []
    p = s2c / TCP(sport=sport, dport=8080, flags="S", seq=seq_c); p.time = base; pkts.append(p)
    p = c2s / TCP(sport=8080, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1); p.time = base + 0.001; pkts.append(p)
    p = s2c / TCP(sport=sport, dport=8080, flags="A", seq=seq_c + 1, ack=seq_s + 1); p.time = base + 0.002; pkts.append(p)
    req = (f"GET {uri} HTTP/1.1\r\nHost: {SERVER}:8080\r\n"
           f"User-Agent: {ua}\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()
    p = s2c / TCP(sport=sport, dport=8080, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(req)
    p.time = base + 0.01; pkts.append(p)
    body = b"<html><body>ok</body></html>"
    resp = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    p = c2s / TCP(sport=8080, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1 + len(req)) / Raw(resp)
    p.time = base + 0.05; pkts.append(p)
    for ff in ("FA", "A", "FA", "A"):                  # 简单收尾
        p = (s2c if ff == "FA" else c2s) / TCP(sport=sport if ff == "FA" else 8080,
                                               dport=8080 if ff == "FA" else sport,
                                               flags=ff, seq=seq_c + 1 + len(req), ack=seq_s + 1 + len(resp))
        p.time = base + 0.06 + 0.001 * len(pkts); pkts.append(p)
    return pkts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="artifacts/pcaps")
    args = ap.parse_args()
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)
    base = datetime(2026, 5, 1, 3, 0, 0).timestamp()
    wrpcap(str(out / "scan-syn.pcap"), scan_pcap(base))
    sqli = ("/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2Cpassword+FROM+users--&Submit=Submit")
    wrpcap(str(out / "sqli-union.pcap"), http_session(base + 10, sqli, "sqlmap/1.7#stable", 55222))
    wrpcap(str(out / "benign.pcap"),
           http_session(base + 20, "/index.php", "Mozilla/5.0 (X11; Linux x86_64)", 55223))
    print(f"[gen] 三段 pcap 已生成到 {out}/：")
    print(f"[gen]   scan-syn.pcap   200 包——SYN 扫描 100 端口（2 秒内）")
    print(f"[gen]   sqli-union.pcap  10 包——一条 union select 注入请求（负对照：benign 不应告警）")
    print(f"[gen]   benign.pcap       10 包——正常 GET /index.php")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
