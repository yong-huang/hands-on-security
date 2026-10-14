#!/usr/bin/env bash
# =============================================================================
# 04 · Web 指纹识别器 —— 三站样本起停 / 指纹识别断言 / favicon 一致性与 curl 对照
# 用法: ./web_finger.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install flask requests（http.server 用标准库）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
BASE_PORT="${LAB_PORT:-8030}"             # 三个样本用连号端口：base / base+1 / base+2
                                          # （8021 常被 macOS 系统服务占用，起点选 8030）
PORT_A="$BASE_PORT"
PORT_B=$((BASE_PORT + 1))
PORT_C=$((BASE_PORT + 2))
WWW_A="/tmp/hosec04-site-a"               # 样本 A 的静态站点根目录
OUT="/tmp/hosec04-finger"                 # 各样本的识别输出，供断言复用
RULES="configs/fingerprint_rules.json"
EXPECT="configs/lab_expectations.json"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

site_ok() {  # $1=端口 $2=页面特征；用特征标记确认「这是本实验的样本站」
    local body
    body="$(curl -s --max-time 2 "http://127.0.0.1:$1/" || true)"
    [[ "$body" == *"$2"* ]]
}
wait_ok() {  # $1=端口 $2=页面特征；就绪等待：最多 4 秒，不裸 sleep
    local i
    for i in $(seq 1 20); do
        site_ok "$1" "$2" && return 0
        sleep 0.2
    done
    return 1
}
pid_is_ours() {                           # $1=pidfile $2=命令特征；PID 可能被复用，核对再杀
    [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null \
        && ps -p "$(cat "$1")" -o command= 2>/dev/null | grep -q "$2"
}
start_site() {                            # $1=名字 $2=pidfile $3=命令特征 $4...=启动命令
    local name="$1" pidfile="$2" pattern="$3"
    shift 3
    if pid_is_ours "$pidfile" "$pattern"; then
        ok "${name} 已在运行 (PID $(cat "$pidfile"))，直接复用"
        return 0
    fi
    rm -f "$pidfile"
    "$@" > "/tmp/hosec04-${name}.log" 2>&1 &
    echo $! > "$pidfile"
    disown 2>/dev/null || true            # 移出作业表：脚本退出时不打扰、不被误杀
}
stop_site() {                             # $1=pidfile $2=命令特征
    local pid i
    if pid_is_ours "$1" "$2"; then
        pid="$(cat "$1")"
        kill "$pid"
        for i in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.2
        done
    fi
    rm -f "$1"
}
cleanup_sites() {                         # 回收三个样本（apply 中途失败也不留残留）
    stop_site /tmp/hosec04-a.pid "http.server ${PORT_A}" || true
    stop_site /tmp/hosec04-b.pid "lab_samples.py flask" || true
    stop_site /tmp/hosec04-c.pid "lab_samples.py mockcms" || true
}

do_apply() {
    step "apply" "启动三个样本站（${PORT_A}=http.server  ${PORT_B}=flask  ${PORT_C}=Apache/PHP 仿真）"
    mkdir -p "$WWW_A"
    echo '<h1>实验 04 · Python http.server 样本</h1>' > "$WWW_A/index.html"

    start_site a /tmp/hosec04-a.pid "http.server ${PORT_A}" \
        "$PY" -m http.server "$PORT_A" --bind 127.0.0.1 --directory "$WWW_A"
    start_site b /tmp/hosec04-b.pid "lab_samples.py flask" \
        "$PY" lab_samples.py flask --port "$PORT_B"
    start_site c /tmp/hosec04-c.pid "lab_samples.py mockcms" \
        "$PY" lab_samples.py mockcms --port "$PORT_C"

    if ! wait_ok "$PORT_A" "Python http.server 样本"; then
        tail -3 /tmp/hosec04-a.log 2>/dev/null || true
        cleanup_sites                        # 回收已起的站点，不留残留
        die "样本 A 4 秒内未就绪（端口 ${PORT_A} 可能被占用：lsof -i :${PORT_A}）"
    fi
    if ! wait_ok "$PORT_B" "LabBlog"; then
        tail -3 /tmp/hosec04-b.log 2>/dev/null || true
        cleanup_sites
        die "样本 B 4 秒内未就绪（端口 ${PORT_B} 可能被占用：lsof -i :${PORT_B}）"
    fi
    if ! wait_ok "$PORT_C" "MockCMS"; then
        tail -3 /tmp/hosec04-c.log 2>/dev/null || true
        cleanup_sites
        die "样本 C 4 秒内未就绪（端口 ${PORT_C} 可能被占用：lsof -i :${PORT_C}）"
    fi
    ok "三站就绪（A http.server / B flask / C Apache+PHP 仿真）"
}

do_observe() {
    step "observe" "指纹识别：三个样本站（响应头 + HTML 特征 + favicon md5）"
    "$PY" web_finger.py "http://127.0.0.1:$PORT_A" -r "$RULES" | tee "$OUT-a.txt"
    "$PY" web_finger.py "http://127.0.0.1:$PORT_B" -r "$RULES" | tee "$OUT-b.txt"
    "$PY" web_finger.py "http://127.0.0.1:$PORT_C" -r "$RULES" | tee "$OUT-c.txt"

    "$PY" - "$EXPECT" "$OUT-a.txt" "$OUT-b.txt" "$OUT-c.txt" <<'PY' || die "识别断言失败（漏报见上）"
import json, sys
conf = json.load(open(sys.argv[1], encoding="utf-8"))
bad = 0
for sample, path in zip(conf["samples"], sys.argv[2:5]):
    hits = "\n".join(l for l in open(path, encoding="utf-8") if l.startswith("[HIT]"))
    missing = [e for e in sample["expect"] if e not in hits]
    got = len(sample["expect"]) - len(missing)
    mark = "✅" if not missing else "❌"
    extra = f"，漏: {missing}" if missing else ""
    print(f"  {mark} {sample['name']}（:{sample['port']}）命中 {got}/{len(sample['expect'])}{extra}")
    bad += bool(missing)
sys.exit(1 if bad else 0)
PY
    ok "三站指纹 3/3 识别正确（共 9 条规则命中）"

    step "observe" "favicon hash 一致性：同一站点两次运行结果应相同"
    local md5_b1 md5_b2 md5_c
    "$PY" web_finger.py "http://127.0.0.1:$PORT_B" -r "$RULES" > "$OUT-b2.txt"
    md5_b1="$(grep -o 'md5 [0-9a-f]*' "$OUT-b.txt" | head -1 | cut -d' ' -f2)"
    md5_b2="$(grep -o 'md5 [0-9a-f]*' "$OUT-b2.txt" | head -1 | cut -d' ' -f2)"
    md5_c="$(grep -o 'md5 [0-9a-f]*' "$OUT-c.txt" | head -1 | cut -d' ' -f2)"
    [ -n "$md5_b1" ] || die "样本 B 未取到 favicon md5"
    [ "$md5_b1" = "$md5_b2" ] || die "同一站点两次 md5 不一致：${md5_b1} vs ${md5_b2}"
    ok "同一站点两次一致：$md5_b1"
    [ "$md5_b1" != "$md5_c" ] || die "不同样本的 favicon md5 不应相同"
    ok "不同站点指纹不同：B=${md5_b1}  C=${md5_c}"
    grep -q "favicon.ico 未提供" "$OUT-a.txt" || die "样本 A 无 favicon，应标注未提供"
    ok "样本 A 未提供 favicon，正确标注跳过（HTTP 404）"

    step "observe" "curl 对照：样本 C 的 Server 头逐字一致"
    local hdr_tool hdr_curl
    hdr_tool="$(grep '^\[HEAD\] Server:' "$OUT-c.txt" | head -1 | sed 's/^\[HEAD\] //')"
    hdr_curl="$(curl -s -D - -o /dev/null "http://127.0.0.1:$PORT_C/" | tr -d '\r' | grep -i '^Server:')"
    [ "$hdr_tool" = "$hdr_curl" ] || die "Server 头不一致：tool=[$hdr_tool] curl=[$hdr_curl]"
    ok "一致：$hdr_tool"
}

do_clean() {
    step "clean" "停止三个样本站，端口 ${PORT_A}/${PORT_B}/${PORT_C} 应关闭"
    cleanup_sites
    if site_ok "$PORT_A" "Python http.server 样本"; then die "样本 A 仍在响应（可能不是本脚本起的进程）"; fi
    if site_ok "$PORT_B" "LabBlog"; then die "样本 B 仍在响应（可能不是本脚本起的进程）"; fi
    if site_ok "$PORT_C" "MockCMS"; then die "样本 C 仍在响应（可能不是本脚本起的进程）"; fi
    ok "三站已停止，环境复原"
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
