#!/usr/bin/env python3
"""21 · 生成含 C2 心跳的测试 pcap（scapy 离线构造，无需 root）

场景：内网主机 10.20.30.40 被植入——每 30 秒向 beacon.cdn-analytics.net
（203.0.113.99）发一次等长 POST 心跳；同时多台「正常用户」在浏览网站，
以及一批随机域名的 DNS 查询（DGA 特征）。时间线固定，结果可复现。
"""
import argparse
import random
from datetime import datetime
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP, wrpcap

BASE = datetime(2026, 5, 2, 3, 0, 0).timestamp()
VICTIM = "10.20.30.40"
C2_IP = "203.0.113.99"
C2_HOST = "beacon.cdn-analytics.net"
RESOLVER = "10.20.30.53"

BEACON_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
CHROME_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"
SAFARI_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.5 Safari/605.1.15")
EDGE_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67")
CURL_UA = "curl/8.4.0"
PY_UA = "python-requests/2.31.0"

# (客户端, 目标主机, 目标 IP, UA, 次数, 路径) —— 次数互不相同，供 Top5 对账
NORMAL = [
    ("192.168.7.10", "www.example.org", "198.51.100.10", CHROME_UA, 12, "/"),
    ("192.168.7.11", "api.example.net", "198.51.100.20", FIREFOX_UA, 9, "/v1/items"),
    ("192.168.7.12", "static.example.net", "198.51.100.30", SAFARI_UA, 6, "/img/logo.png"),
    ("192.168.7.10", "img.example.org", "198.51.100.40", EDGE_UA, 5, "/cover.jpg"),
    ("192.168.7.13", "api.example.net", "198.51.100.20", CURL_UA, 4, "/v1/health"),
    ("192.168.7.14", "status.example.net", "198.51.100.50", PY_UA, 3, "/status.json"),
]
DGA_QUERIES = ["xj3kq9wzmv7p.net", "kq7mz4tpl2.top", "v8nq3xzr9km.net"]


def mac(ip):
    a, b = ip.split(".")[-2:]
    return f"02:00:00:00:{int(a):02x}:{int(b):02x}"


def http_session(src, dst, sport, dport, ts, raw_req, raw_resp):
    """一次完整 HTTP 会话：三次握手 + 请求 + 响应 + 双向 FIN。"""
    seq_c = random.randint(1_000_000, 9_000_000)
    seq_s = random.randint(1_000_000, 9_000_000)
    epc, eps = Ether(src=mac(src), dst=mac(dst)), Ether(src=mac(dst), dst=mac(src))
    ipc, ips = IP(src=src, dst=dst), IP(src=dst, dst=src)
    pkts = []

    def add(p, dt):
        p.time = ts + dt
        pkts.append(p)

    add(epc / ipc / TCP(sport=sport, dport=dport, flags="S", seq=seq_c), 0)
    add(eps / ips / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1), 0.001)
    add(epc / ipc / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1), 0.002)
    add(epc / ipc / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(raw_req), 0.01)
    ack2 = seq_c + 1 + len(raw_req)
    add(eps / ips / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s + 1, ack=ack2) / Raw(raw_resp), 0.05)
    ack3 = seq_s + 1 + len(raw_resp)
    add(eps / ips / TCP(sport=dport, dport=sport, flags="FA", seq=ack3, ack=ack2), 0.06)
    add(epc / ipc / TCP(sport=sport, dport=dport, flags="A", seq=ack2, ack=ack3 + 1), 0.061)
    add(epc / ipc / TCP(sport=sport, dport=dport, flags="FA", seq=ack2, ack=ack3 + 1), 0.062)
    add(eps / ips / TCP(sport=dport, dport=sport, flags="A", seq=ack3 + 1, ack=ack2 + 1), 0.063)
    return pkts


def dns_query(src, ts, qname, answer_ip=None):
    """一次 DNS 查询与应答；answer_ip 为 None 时返回 NXDOMAIN（3）。"""
    sid = random.randint(1, 65535)
    sport = random.randint(30000, 40000)
    q = Ether(src=mac(src), dst=mac(RESOLVER)) / IP(src=src, dst=RESOLVER) / \
        UDP(sport=sport, dport=53) / DNS(id=sid, rd=1, qd=DNSQR(qname=qname))
    q.time = ts
    if answer_ip:
        r = Ether(src=mac(RESOLVER), dst=mac(src)) / IP(src=RESOLVER, dst=src) / \
            UDP(sport=53, dport=sport) / DNS(id=sid, qr=1, aa=1, rd=1, ra=1,
                                             qd=DNSQR(qname=qname),
                                             an=DNSRR(rrname=qname, ttl=300, rdata=answer_ip))
    else:
        r = Ether(src=mac(RESOLVER), dst=mac(src)) / IP(src=RESOLVER, dst=src) / \
            UDP(sport=53, dport=sport) / DNS(id=sid, qr=1, aa=1, rd=1, ra=1, rcode=3,
                                             qd=DNSQR(qname=qname))
    r.time = ts + 0.01
    return [q, r]


def request(method, host, path, ua, body=b""):
    head = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Accept: */*\r\nConnection: close\r\n")
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    return (head + "\r\n").encode() + body


def response(body=b"ok"):
    return (f"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode() + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="artifacts/pcaps")
    args = ap.parse_args()
    random.seed(21)
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)
    pkts = []
    sport = 40000

    # ① C2 心跳：先解析域名，再每 30 秒 ±0.15s 一次等长 POST
    pkts += dns_query(VICTIM, BASE - 2, C2_HOST, C2_IP)
    for i in range(7):
        ts = BASE + i * 30 + random.uniform(-0.15, 0.15)
        body = b"nonce=" + random.randbytes(8).hex().encode() + b"&v=1"
        sport += 1
        pkts += http_session(VICTIM, C2_IP, sport, 80, ts,
                             request("POST", C2_HOST, "/api/v2/ping", BEACON_UA, body),
                             response(b"OK"))

    # ② 正常浏览：每台主机先解析一次域名，再不定时发请求
    resolved = set()
    for client, host, ip, ua, count, path in NORMAL:
        if host not in resolved:
            pkts += dns_query(client, BASE - 1, host, ip)
            resolved.add(host)
        for ts in sorted(random.uniform(5, 380) for _ in range(count)):
            sport += 1
            pkts += http_session(client, ip, sport, 80, BASE + ts,
                                 request("GET", host, path, ua), response())

    # ③ DGA 特征：受害主机频繁查询随机域名（全部 NXDOMAIN）
    for i, qname in enumerate(DGA_QUERIES):
        pkts += dns_query(VICTIM, BASE + 60 + i * 40, qname, None)

    pkts.sort(key=lambda p: p.time)
    wrpcap(str(out / "c2-beacon.pcap"), pkts)
    print(f"[gen] c2-beacon.pcap（{len(pkts)} 包）→ {out}/")
    print(f"[gen] 植入：{VICTIM} → {C2_HOST} 每 30s 一次等长 POST（7 次心跳）")
    print(f"[gen] 正常流量：{sum(x[4] for x in NORMAL)} 次浏览 + {len(DGA_QUERIES)} 个随机域名查询")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
