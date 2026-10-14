#!/usr/bin/env bash
# =============================================================================
# 10 · 自建 CA 与 TLS 全流程 —— 证书链生成 / HTTPS 服务 / 三种信任场景校验
# 用法: ./tls_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: openssl（优先 Homebrew openssl@3）；python3 标准库（ssl/http.server）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
PORT="${LAB_PORT:-8443}"
ART="artifacts"                           # 证书与响应全部放这里（.gitignore 已忽略）
CA="$ART/ca"
PIDFILE="/tmp/hosec10-tls.pid"
CONF="configs/ca.cnf"

# 找 openssl：优先 openssl@3（Homebrew），退回系统
OSSL="${OPENSSL_BIN:-}"
if [ -z "$OSSL" ]; then
    for c in /opt/homebrew/opt/openssl@3/bin/openssl /opt/homebrew/opt/openssl/bin/openssl \
             "$(command -v openssl 2>/dev/null || true)"; do
        if [ -n "$c" ] && [ -x "$c" ]; then OSSL="$c"; break; fi
    done
fi

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

tls_up() {  # 任意证书的 TLS 可达性探针（仅用于等待启动）
    curl -sk -o /dev/null --max-time 2 "https://localhost:$PORT/"
}
pid_is_ours() {                           # PID 可能被复用，核对命令再杀
    [ -f "$PIDFILE" ] \
        && kill -0 "$(cat "$PIDFILE")" 2>/dev/null \
        && ps -p "$(cat "$PIDFILE")" -o command= 2>/dev/null | grep -q "tls_server.py"
}

do_apply() {
    step "apply" "openssl 生成证书链：自建根 CA + SAN 服务器证书 + 对照 CA"
    [ -n "$OSSL" ] || die "找不到 openssl（可设置 OPENSSL_BIN）"
    ver="$("$OSSL" version)"
    case "$ver" in
        *"OpenSSL 3"*) ;;
        *) die "本实验需要 OpenSSL 3（当前：${ver%% *}）：brew install openssl@3 或设置 OPENSSL_BIN" ;;
    esac
    echo "  ℹ️  openssl：${OSSL}（$(echo "$ver" | cut -d' ' -f1-2)）"
    "$PY" -c "import ssl, http.server" 2>/dev/null || die "python3 缺 ssl/http.server"
    mkdir -p "$CA"

    "$OSSL" req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CA/ca.key" -out "$CA/ca.crt" -days 365 \
        -config "$CONF" -extensions v3_ca -subj "/CN=hosec-lab-ca" 2>/dev/null
    "$OSSL" req -newkey rsa:2048 -nodes \
        -keyout "$CA/server.key" -out "$CA/server.csr" \
        -config "$CONF" -subj "/CN=localhost" 2>/dev/null
    "$OSSL" x509 -req -in "$CA/server.csr" -CA "$CA/ca.crt" -CAkey "$CA/ca.key" \
        -CAcreateserial -out "$CA/server.crt" -days 365 \
        -extfile "$CONF" -extensions v3_server 2>/dev/null
    "$OSSL" req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CA/wrong-ca.key" -out "$CA/wrong-ca.crt" -days 365 \
        -config "$CONF" -extensions v3_ca -subj "/CN=wrong-ca" 2>/dev/null
    ok "根 CA（hosec-lab-ca）、服务器证书（SAN: localhost/127.0.0.1）、对照 CA 就绪"

    if pid_is_ours; then
        ok "HTTPS 服务已在运行 (PID $(cat "$PIDFILE"))，直接复用"
    else
        rm -f "$PIDFILE"
        "$PY" tls_server.py "$CA/server.crt" "$CA/server.key" "$PORT" \
            > /tmp/hosec10-tls.log 2>&1 &
        echo $! > "$PIDFILE"
        disown 2>/dev/null || true
        local i
        for i in $(seq 1 20); do
            tls_up && break
            sleep 0.2
        done
        tls_up || { tail -3 /tmp/hosec10-tls.log 2>/dev/null || true; die "HTTPS 服务 4 秒内未就绪（端口 $PORT 可能被占用）"; }
        ok "HTTPS 服务就绪：https://localhost:${PORT}（证书：$CA/server.crt）"
    fi
}

do_observe() {
    local code
    step "observe" "场景一：客户端信任实验 CA（--cacert ca.crt）→ 应 200"
    code="$(curl -s --cacert "$CA/ca.crt" -o "$ART/resp.txt" -w '%{http_code}' \
        "https://localhost:$PORT/")"
    [ "$code" = "200" ] || die "预期 200，实得 $code"
    cat "$ART/resp.txt"
    ok "校验通过并取回内容（HTTP ${code}）"

    step "observe" "场景二：不带 --cacert（系统信任库不认识这把 CA）→ 应拒绝"
    if curl -sS -o /dev/null --max-time 5 "https://localhost:$PORT/" 2> "$ART/curl-noca.err"; then
        die "系统信任库竟然通过了（不该发生）"
    fi
    grep -qi "SSL certificate problem" "$ART/curl-noca.err" || die "错误信息与预期不符"
    sed 's/^/  /' "$ART/curl-noca.err"
    ok "按预期被拒（错误信息见上：证书链不成立于系统信任库）"

    step "observe" "场景三：信任另一套 CA（wrong-ca.crt）→ 同样应拒绝"
    if curl -sS -o /dev/null --max-time 5 --cacert "$CA/wrong-ca.crt" \
        "https://localhost:$PORT/" 2> "$ART/curl-wrong.err"; then
        die "错误 CA 竟然通过了（不该发生）"
    fi
    sed 's/^/  /' "$ART/curl-wrong.err"
    ok "按预期被拒：签名链对不上，证书与信任锚必须同源"

    step "observe" "openssl verify 与 Python 客户端三场景（同一套证书、同一结论）"
    "$OSSL" verify -CAfile "$CA/ca.crt" "$CA/server.crt" | tee "$ART/verify.out"
    grep -q ": OK" "$ART/verify.out" || die "openssl verify 未返回 OK"
    "$PY" tls_client.py --port "$PORT" --ca "$CA/ca.crt" | tee -a "$ART/verify.out"
    if "$PY" tls_client.py --port "$PORT" > "$ART/client-noca.out" 2>&1; then
        die "Python 无自定义 CA 竟然成功"
    fi
    if "$PY" tls_client.py --port "$PORT" --ca "$CA/wrong-ca.crt" > "$ART/client-wrong.out" 2>&1; then
        die "Python 错误 CA 竟然成功"
    fi
    grep -q "校验失败" "$ART/client-noca.out" || die "客户端错误输出异常"
    echo "  ---- 系统信任库 ----"; sed 's/^/  /' "$ART/client-noca.out"
    echo "  ---- 错误 CA ----"; sed 's/^/  /' "$ART/client-wrong.out"
    ok "同源校验通过，异源两例均拒——证书链的判定是确定性的"
}

do_clean() {
    step "clean" "停止 HTTPS 服务，清理证书等生成物"
    if pid_is_ours; then
        kill "$(cat "$PIDFILE")"
        local i
        for i in $(seq 1 20); do
            tls_up || break
            sleep 0.2
        done
    fi
    rm -f "$PIDFILE"
    if tls_up; then die "端口 $PORT 仍有 TLS 响应（可能不是本脚本起的进程）"; fi
    rm -rf "$ART"
    ok "服务已停、证书已清（artifacts/ 可随时重建），环境复原"
}

main() {
    local target="${1:-all}"
    case "$target" in
        apply)   do_apply ;;
        observe) do_observe ;;
        clean)   do_clean ;;
        all)     do_apply; do_observe; do_clean ;;
        *) echo "可用: apply | observe | clean | all" >&2; exit 1 ;;
    esac
}
main "$@"
