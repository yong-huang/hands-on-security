#!/usr/bin/env python3
"""15 · SSRF 靶：一个「帮内网取数」的脆弱服务（默认 127.0.0.1:8602）

/fetch?url=... 不做任何校验——http(s) 与 file:// 都由服务端代取。
攻击者拿它当跳板：探测内网端口（响应差异侧信道）、读宿主文件（file://）。
只用于本实验的本地靶场。
"""
import argparse
import urllib.request

from flask import Flask
from flask import request as req

app = Flask(__name__)


@app.get("/")
def home():
    return (
        "<h1>内网取数服务</h1>\n"
        "<p>用法：/fetch?url=http://... 或 file:///...</p>\n"
        "<p>开发备注：先支持 http 与 file，内部调用什么都能取——白名单待加。</p>\n"
    )


@app.get("/fetch")
def fetch():
    url = req.args.get("url", "")
    if not url:
        return "用法: /fetch?url=...\n", 400
    try:
        resp = urllib.request.urlopen(url, timeout=3)
        body = resp.read(1200)
        return f"[目标 {url} 取回 {len(body)} 字节（最多 1200）]\n" + body.decode("utf-8", "replace")
    except Exception as e:
        raw = str(e)
        safe = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in raw)
        return f'ERROR: {type(e).__name__}("{safe[:160]}")\n'


@app.get("/ping")
def ping():
    return "ok", 200


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8602)
    args = ap.parse_args()
    print(f"[*] SSRF 靶已启动：http://127.0.0.1:{args.port}/fetch?url=...", flush=True)
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
