#!/usr/bin/env python3
"""03 · 实验靶站：真实路径 + 软 404 陷阱

用法:
    python3 lab_site.py [--host 127.0.0.1] [--port 8010]

路径清单住在 configs/lab_site_paths.json：脚本 dir_brute.sh 会用它做断言，
所以「靶站有什么」只维护一份。行为设计（都是真实世界见过的形态）：
  - 已知目录不带斜杠（如 /admin）→ 301 补斜杠，这是目录存在的信号；
  - 顶层未知路径 → 200 + 友好页（软 404 陷阱，逼爆破器做基线降噪）；
  - 已知目录内部的未知路径 → 真 404（模拟应用自身的路由行为）；
  - /api/status 是 JSON、robots.txt 是纯文本，状态多样性都在清单里声明。
"""
import argparse
import json
import logging
from pathlib import Path

from flask import Flask, Response, redirect

CONF = Path(__file__).parent / "configs" / "lab_site_paths.json"


def load_conf():
    with open(CONF, encoding="utf-8") as f:
        return json.load(f)


def build_app(conf):
    app = Flask(__name__)
    pages = {e["path"]: e for e in conf["paths"]}
    # 目录名（去掉尾部斜杠）：/admin/、/admin/panel/ … 用于 301 与嵌套 404 判定
    dirs = {p.rstrip("/") for p in pages if p.endswith("/")}
    soft = conf["soft_404"]

    def page(body, status=200, ctype="text/html; charset=utf-8"):
        return Response(body, status=status, content_type=ctype)

    @app.route("/", defaults={"sub": ""})
    @app.route("/<path:sub>")
    def handler(sub):
        if sub in pages:                                  # 精确命中预置路径
            e = pages[sub]
            return page(e["body"], e.get("status", 200), e.get("content_type"))
        if sub in dirs:                                   # 目录缺斜杠 → 301
            return redirect(f"/{sub}/", code=301)
        if any(sub.startswith(d + "/") for d in dirs):    # 目录内部的未知路径
            return page("<h1>404 Not Found</h1><p>子目录内未知路径：真 404，不是软 404。</p>", 404)
        return page(soft["body"], soft.get("status", 200))  # 顶层未知 → 软 404 陷阱

    return app


def main():
    parser = argparse.ArgumentParser(description="实验 03 靶站（仅本地使用）")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8010)
    args = parser.parse_args()

    logging.getLogger("werkzeug").setLevel(logging.WARNING)  # 关掉逐请求日志
    conf = load_conf()
    app = build_app(conf)
    print(f"[*] 靶站 http://{args.host}:{args.port}："
          f"{len(conf['paths'])} 条预置路径 + 软 404 陷阱", flush=True)
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
