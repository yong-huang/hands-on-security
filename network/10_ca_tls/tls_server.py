#!/usr/bin/env python3
"""10 · HTTPS 测试服务：把 HTTP 服务包进 TLS（仅监听 127.0.0.1）

用法:
    python3 tls_server.py artifacts/server.crt artifacts/server.key [端口]

证书由 tls_lab.sh 用自建 CA 签发；本服务只用于本机实验。
"""
import http.server
import ssl
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello over TLS: certificate verified by hosec lab CA\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):          # 日志静音（脚本另有输出）
        pass


def main():
    cert, key = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8443

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[*] HTTPS 服务已启动：https://localhost:{port}（证书 {cert}）", flush=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    threading.Event().wait()               # 挂在主线程等 SIGTERM/SIGKILL


if __name__ == "__main__":
    main()
