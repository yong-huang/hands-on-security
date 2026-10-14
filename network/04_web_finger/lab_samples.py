#!/usr/bin/env python3
"""04 · 实验样本站：Flask 博客站 + Apache/PHP 仿真站

用法:
    python3 lab_samples.py flask   --port 8022   # Werkzeug/Flask 栈的博客样本
    python3 lab_samples.py mockcms --port 8023   # 模拟 Apache + PHP + MockCMS 的样本

两个 favicon 都是固定字节（实验预置），供 favicon md5 指纹规则命中。
仿真站刻意模仿真实世界的泄漏面：Server 头、X-Powered-By、Set-Cookie、
meta generator 与 favicon——真实环境中这些都由组件自带的。
"""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 实验预置的两个 favicon（固定字节，md5 已写进 configs/fingerprint_rules.json）
FAVICON_LABLOG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAI0lEQVR4nGPUWjiDgRTARJJqhlEN"
    "xAEmItXBwagGYgDJoQQAcEgBg+NO1cAAAAAASUVORK5CYII=")
FAVICON_MOCKCMS = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAU0lEQVR4nGP8//8/AzZwxkccq7jJ"
    "lpckqWdioDFgGrWAEBgNIoKA8bS3GFXSuwkO9aNxQBCMBtHABxHjaH1ACIwm0xEQRIyj9cHwj2Sm"
    "UQsYCAAAAl0aj0D7zq8AAAAASUVORK5CYII=")

LABLOG_HTML = """<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="generator" content="LabBlog 2.1">
<title>LabBlog · 实验 04 样本站</title>
</head><body data-app="lab-blog">
<h1>LabBlog</h1>
<p>一个用 Flask 搭的示例博客站，供指纹识别实验使用。</p>
</body></html>
"""

MOCKCMS_HTML = """<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="generator" content="MockCMS 1.0">
<title>MockCMS 演示站</title>
</head><body>
<h1>MockCMS</h1>
<p>模拟传统 LAMP 栈的演示站点（实验 04 样本）。</p>
<p><a href="/index.php">进入首页</a></p>
</body></html>
"""


def run_flask(port):
    from flask import Flask, Response

    app = Flask(__name__)

    @app.route("/")
    def index():
        return LABLOG_HTML

    @app.route("/favicon.ico")
    def favicon():
        return Response(FAVICON_LABLOG, content_type="image/png")

    print(f"[*] Flask 样本站 http://127.0.0.1:{port}", flush=True)
    app.run(host="127.0.0.1", port=port, debug=False)


class MockCmsHandler(BaseHTTPRequestHandler):
    """模拟 Apache 2.4 + PHP 8.2 的响应特征。"""

    server_version = "Apache/2.4.57 (Debian)"
    server_name = "mockcms"

    def version_string(self):                       # 默认会拼上 Python 版本，去掉
        return self.server_version

    def _send(self, code, raw, ctype, body=True):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/8.2.7")     # 真实 PHP 默认吐这个
        self.send_header("Set-Cookie", "PHPSESSID=3f1c9a2b7d; path=/")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if body:
            self.wfile.write(raw)

    def _route(self, body):
        if self.path == "/":
            self._send(200, MOCKCMS_HTML.encode("utf-8"), "text/html; charset=utf-8", body)
        elif self.path == "/favicon.ico":
            self._send(200, FAVICON_MOCKCMS, "image/png", body)
        else:
            self._send(404, b"<h1>404 Not Found</h1>", "text/html; charset=utf-8", body)

    def do_GET(self):
        self._route(body=True)

    def do_HEAD(self):                                 # 与真实服务器一样支持 HEAD
        self._route(body=False)

    def log_message(self, *args):                   # 请求日志静音（脚本另有日志文件）
        pass


def run_mockcms(port):
    server = ThreadingHTTPServer(("127.0.0.1", port), MockCmsHandler)
    print(f"[*] MockCMS 仿真站 http://127.0.0.1:{port}", flush=True)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description="实验 04 样本站（仅本地使用）")
    parser.add_argument("profile", choices=["flask", "mockcms"])
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if args.profile == "flask":
        run_flask(args.port)
    else:
        run_mockcms(args.port)


if __name__ == "__main__":
    main()
