#!/usr/bin/env bash
# =============================================================================
# 01 · 多线程 TCP 端口扫描器 —— 靶场起停 / connect 扫描与 banner 抓取 / nmap 对照 / 限速演示
# 用法: ./tcp_port_scanner.sh [apply|observe|clean|all]   (默认 all)
# 前置: python3（标准库即可）；nmap 可选（有则做一致性对照）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
PORT="${LAB_PORT:-8000}"                  # 演示靶端口（在扫描范围内）
RANGE="${SCAN_RANGE:-1-10000}"            # 本机演示扫描范围（覆盖 8000）
WWW="/tmp/hosec01-www"                    # 靶站根目录
PIDFILE="/tmp/hosec01-http.pid"           # 靶站 PID，clean 精准回收自己的进程
LOG="/tmp/hosec01-http.log"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }
port_open() { nc -z 127.0.0.1 "$1" >/dev/null 2>&1; }   # macOS 自带 nc
pid_is_ours() {                                         # PID 可能被系统复用，必须核对命令再杀
    [ -f "$PIDFILE" ] \
        && kill -0 "$(cat "$PIDFILE")" 2>/dev/null \
        && ps -p "$(cat "$PIDFILE")" -o command= 2>/dev/null | grep -q "http.server $PORT"
}

# ---- 就绪等待：最多 4 秒，不裸 sleep ----
wait_port() {
    local i
    for i in $(seq 1 20); do
        port_open "$PORT" && return 0
        sleep 0.2
    done
    return 1
}

do_apply() {
    step "apply" "启动本地 HTTP 靶服务 (127.0.0.1:$PORT)"
    if pid_is_ours; then
        ok "靶服务已在运行 (PID $(cat "$PIDFILE"))，直接复用"
        return 0
    fi
    rm -f "$PIDFILE"                      # 陈旧 pidfile（进程已死）直接清掉
    mkdir -p "$WWW"
    echo "<h1>hands-on-security · 实验 01 靶站</h1>" > "$WWW/index.html"
    "$PY" -m http.server "$PORT" --bind 127.0.0.1 --directory "$WWW" > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    disown 2>/dev/null || true            # 移出作业表：脚本退出时不打扰、不被误杀
    wait_port || { cat "$LOG"; die "靶服务 4 秒内未就绪（端口 $PORT 可能被占用）"; }
    ok "靶服务就绪 (PID $(cat "$PIDFILE")，日志 $LOG)"
}

do_observe() {
    step "observe" "connect 扫描: 127.0.0.1 端口 ${RANGE}，100 线程"
    local out elapsed
    out="$("$PY" port_scanner.py 127.0.0.1 -p "$RANGE" -t 100)"
    echo "$out"
    grep -q "^\[+\] ${PORT}/tcp open" <<<"$out" || die "未报出 $PORT 端口"
    ok "报出 ${PORT} 端口（这就是靶服务）"
    grep -q "Server: SimpleHTTP" <<<"$out" || die "未抓到 HTTP banner"
    ok "banner 抓取成功（Server: SimpleHTTP... 来自主动 HEAD 探测）"

    elapsed="$(sed -n 's/.*耗时 \([0-9.]*\)s.*/\1/p' <<<"$out" | tail -1)"
    "$PY" -c "import sys; sys.exit(0 if float('$elapsed') < 10 else 1)" \
        || die "扫描耗时 ${elapsed}s 超过 10 秒"
    ok "扫描耗时 ${elapsed}s < 10s"

    step "observe" "nmap 同范围对照（开放端口集合应完全一致）"
    if ! command -v nmap >/dev/null 2>&1; then
        echo "  ℹ️  未安装 nmap，跳过对照（brew install nmap 后可补验）"
        return 0
    fi
    local mine theirs
    mine="$(grep '^\[+\]' <<<"$out" | awk '{print $2}' | cut -d/ -f1 | sort -n | tr '\n' ' ')"
    theirs="$(nmap -p "$RANGE" -T4 127.0.0.1 2>/dev/null \
        | awk '$2=="open"{split($1,a,"/"); print a[1]}' | sort -n | tr '\n' ' ')"
    echo "  自研: $mine"
    echo "  nmap: $theirs"
    [ "$mine" = "$theirs" ] || die "两工具开放端口集合不一致"
    ok "两工具结果一致（$(wc -w <<<"$mine" | tr -d ' ') 个开放端口）"
    echo "  （本机为 macOS，系统服务如 AirTunes/代理端口也会被扫出——这正是资产测绘要看到的）"

    step "observe" "限速演示: 同一批端口 --rate 20（应明显变慢）"
    local slow elapsed_slow
    slow="$("$PY" port_scanner.py 127.0.0.1 -p 7990-8010 --rate 20)"
    grep -q "${PORT}/tcp open" <<<"$slow" || die "限速模式下漏报 $PORT"
    elapsed_slow="$(sed -n 's/.*耗时 \([0-9.]*\)s.*/\1/p' <<<"$slow" | tail -1)"
    echo "  21 个端口 @ 20 次/秒 耗时 ${elapsed_slow}s（不限速时不足 0.1s）"
    "$PY" -c "import sys; sys.exit(0 if float('$elapsed_slow') >= 0.8 else 1)" \
        || die "限速未生效"
    ok "限速生效（全局限速器把并发探测压到设定速率）"
}

do_clean() {
    step "clean" "停止靶服务，端口 ${PORT} 应关闭"
    if pid_is_ours; then                # 只杀确认是自己起的 http.server 进程
        local pid
        pid="$(cat "$PIDFILE")"
        kill "$pid"
        local i
        for i in $(seq 1 20); do
            port_open "$PORT" || break
            sleep 0.2
        done
    fi
    rm -f "$PIDFILE"
    if port_open "$PORT"; then die "端口 ${PORT} 仍被占用（可能不是本脚本起的进程）"; fi
    ok "靶服务已停止，环境复原"
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
