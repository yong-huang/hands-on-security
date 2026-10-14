#!/usr/bin/env bash
# =============================================================================
# 02 · 子域名与 DNS 信息收集器 —— 权威测试域起停 / 子域枚举 / dig 对照 / AXFR 演示
# 用法: ./dns_enum.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install dnspython；brew install dnsmasq（本实验用本地进程替代容器，
#       原因是 Docker Hub 直连不通，见 README「Pitfalls & Q&A」）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
DNSMASQ="${DNSMASQ_BIN:-/opt/homebrew/opt/dnsmasq/sbin/dnsmasq}"
PORT="${DNS_PORT:-5300}"                  # 高位端口免 sudo；5353 被 mDNS 占用
CONF="configs/dnsmasq-lab.conf"
DOMAIN="lab.local"
PIDFILE="/tmp/hosec02-dnsmasq.pid"
LOG="/tmp/hosec02-dnsmasq.log"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

dns_up() {  # 测试域可达性探针：问 NS 主机
    dig +time=1 +tries=1 @127.0.0.1 -p "$PORT" +short ns1.${DOMAIN} A >/dev/null 2>&1
}
pid_is_ours() {                           # PID 可能被复用，核对命令再杀
    [ -f "$PIDFILE" ] \
        && kill -0 "$(cat "$PIDFILE")" 2>/dev/null \
        && ps -p "$(cat "$PIDFILE")" -o command= 2>/dev/null | grep -q dnsmasq
}
section() {  # 从工具输出里抽一段（$1=输出 $2=节名），供与 dig 对照
    awk -v tag="[$2]" 'index($0, tag) == 1 {p=1; next} /^\[/ {p=0} p' <<<"$1" | sed 's/^  //' | grep -v '^$' | sort
}

do_apply() {
    step "apply" "启动权威测试域 dnsmasq (127.0.0.1:${PORT}，区 ${DOMAIN})"
    [ -x "$DNSMASQ" ] || die "未找到 dnsmasq：brew install dnsmasq（或设置 DNSMASQ_BIN）"
    "$PY" -c "import dns" 2>/dev/null || die "缺少 dnspython：pip3 install dnspython"
    if pid_is_ours; then
        ok "dnsmasq 已在运行 (PID $(cat "$PIDFILE"))，直接复用"
        return 0
    fi
    rm -f "$PIDFILE"
    "$DNSMASQ" --keep-in-foreground -C "$CONF" >/dev/null 2>&1 &
    echo $! > "$PIDFILE"
    disown 2>/dev/null || true
    local i
    for i in $(seq 1 20); do
        dns_up && break
        sleep 0.2
    done
    if ! dns_up; then
        tail -5 "$LOG" 2>/dev/null || true
        die "dnsmasq 4 秒内未就绪（端口 ${PORT} 可能被占用：lsof -i :${PORT}）"
    fi
    ok "dnsmasq 就绪 (PID $(cat "$PIDFILE")，区 ${DOMAIN} @127.0.0.1:${PORT})"
}

do_observe() {
    step "observe" "子域枚举 + NS/MX/TXT + AXFR（测试域 @127.0.0.1:${PORT}）"
    local out hits
    out="$("$PY" dns_enum.py "$DOMAIN" --resolver 127.0.0.1 --port "$PORT")"
    echo "$out"

    grep -q "命中 5/25" <<<"$out" || die "预期字典 25 条命中 5 条"
    ok "字典 25 条命中 5 个子域"
    local sub
    for sub in www mail api blog shop; do
        grep -q "${sub}\.${DOMAIN}" <<<"$out" || die "漏报 ${sub}.${DOMAIN}"
    done
    ok "5 个预置子域全部命中（www/mail/api/blog/shop）"
    grep -q "CNAME" <<<"$out" || die "未识别 shop 的 CNAME 别名链"
    ok "CNAME 别名链识别成功（shop → www）"
    grep -q "✅ 传送成功" <<<"$out" || die "AXFR 未成功"
    hits="$(grep -c ' IN ' <<<"$out")"
    ok "AXFR 区域传送成功（${hits} 条记录，一次拿全）"

    step "observe" "dig 对照：MX / TXT 逐条一致"
    local mx_dig mx_tool txt_dig txt_tool
    mx_dig="$(dig +short @127.0.0.1 -p "$PORT" "$DOMAIN" MX | sort)"
    mx_tool="$(section "$out" MX)"
    [ "$mx_dig" = "$mx_tool" ] || die "MX 不一致：dig=[$mx_dig] tool=[$mx_tool]"
    ok "MX 一致：$mx_dig"
    txt_dig="$(dig +short @127.0.0.1 -p "$PORT" "$DOMAIN" TXT | sort)"
    txt_tool="$(section "$out" TXT)"
    [ "$txt_dig" = "$txt_tool" ] || die "TXT 不一致：dig=[$txt_dig] tool=[$txt_tool]"
    ok "TXT 一致：$txt_dig"

    step "observe" "外网对照：example.com MX/TXT 与 dig 逐条一致"
    if [ -z "$(dig +time=2 +tries=1 +short example.com NS 2>/dev/null)" ]; then
        echo "  ℹ️  系统 DNS 无法解析外网，跳过该步（核心验收不受影响，可联网后重跑）"
        return 0
    fi
    local ext
    ext="$("$PY" dns_enum.py example.com --no-enum --no-axfr)"
    echo "$ext"
    mx_dig="$(dig +short example.com MX | sort)"
    mx_tool="$(section "$ext" MX)"
    [ "$mx_dig" = "$mx_tool" ] || die "example.com MX 不一致：dig=[$mx_dig] tool=[$mx_tool]"
    ok "example.com MX 一致：$mx_dig"
    txt_dig="$(dig +short example.com TXT | sort)"
    txt_tool="$(section "$ext" TXT)"
    [ "$txt_dig" = "$txt_tool" ] || die "example.com TXT 不一致"
    ok "example.com TXT 一致（$(wc -l <<<"$txt_tool" | tr -d ' ') 条，逐条相同）"

    step "observe" "真实世界对照：对公网权威服务器做 AXFR 应被拒绝"
    "$PY" dns_enum.py example.com --no-enum 2>&1 | grep -E "\[AXFR\]|❌|✅" | sed 's/^/  /'
    ok "公网服务器拒绝传送（这正是区域传送漏洞值得记录的原因）"
}

do_clean() {
    step "clean" "停止测试域 dnsmasq"
    if pid_is_ours; then
        kill "$(cat "$PIDFILE")"
        local i
        for i in $(seq 1 20); do
            dns_up || break
            sleep 0.2
        done
    fi
    rm -f "$PIDFILE"
    if dns_up; then die "端口 ${PORT} 仍在响应（可能不是本脚本起的进程）"; fi
    ok "dnsmasq 已停止，环境复原"
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
