#!/usr/bin/env bash
# =============================================================================
# 03 · Web 目录爆破器（mini-dirsearch）—— 靶站起停 / 字典爆破 / 降噪与递归演示 / 逐条复核
# 用法: ./dir_brute.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install flask requests（web 靶站与探测都只用这两个库）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
PORT="${LAB_PORT:-8010}"                  # 演示靶站端口
BASE="http://127.0.0.1:${PORT}"
CONF="configs/lab_site_paths.json"        # 靶站路径清单：靶站与断言共用一份
PIDFILE="/tmp/hosec03-flask.pid"          # 靶站 PID，clean 精准回收自己的进程
LOG="/tmp/hosec03-flask.log"
OUT="/tmp/hosec03-scan.out"               # 各次扫描输出，供断言复用
DVWA="${DVWA_URL:-http://localhost:8612}" # 项目 12 的 DVWA 地址（未就绪自动跳过）

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

site_up() {   # 靶站可达性探针：robots.txt 是预置路径，应返回 200
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${BASE}/robots.txt" || true)" = "200" ]
}
pid_is_ours() {                           # PID 可能被复用，核对命令再杀
    [ -f "$PIDFILE" ] \
        && kill -0 "$(cat "$PIDFILE")" 2>/dev/null \
        && ps -p "$(cat "$PIDFILE")" -o command= 2>/dev/null | grep -q "lab_site.py"
}

do_apply() {
    step "apply" "启动 flask 靶站 (127.0.0.1:${PORT}，软 404 陷阱 + 13 条预置路径)"
    "$PY" -c "import flask" 2>/dev/null || die "缺少 flask：pip3 install flask"
    if pid_is_ours; then
        ok "靶站已在运行 (PID $(cat "$PIDFILE"))，直接复用"
        return 0
    fi
    rm -f "$PIDFILE"                      # 陈旧 pidfile（进程已死）直接清掉
    "$PY" lab_site.py --port "$PORT" > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    disown 2>/dev/null || true            # 移出作业表：脚本退出时不打扰、不被误杀
    local i
    for i in $(seq 1 20); do              # 就绪等待：最多 4 秒，不裸 sleep
        site_up && break
        sleep 0.2
    done
    site_up || { tail -5 "$LOG" 2>/dev/null || true; die "靶站 4 秒内未就绪（端口 ${PORT} 可能被占用：lsof -i :${PORT}）"; }
    ok "靶站就绪 (PID $(cat "$PIDFILE")，日志 $LOG)"
}

do_observe() {
    step "observe" "字典爆破: ${BASE}（默认字典 + 递归一层）"
    "$PY" dir_brute.py "$BASE" -r | tee "$OUT"
    "$PY" - "$CONF" "$OUT" <<'PY' || die "靶站预置路径未全部命中（漏报/多余命中见上）"
import json, re, sys
conf = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {e["path"].rstrip("/") for e in conf["paths"]}
found = set()
for line in open(sys.argv[2], encoding="utf-8"):
    m = re.match(r"\[\+\] /(\S+)", line)
    if m:
        found.add(m.group(1).rstrip("/"))
for p in sorted(expected - found):
    print(f"  漏报: /{p}")
for p in sorted(found - expected):
    print(f"  多余命中: /{p}")
sys.exit(1 if expected - found or found - expected else 0)
PY
    ok "13 条预置路径全部命中且无多余（11 顶层 + 2 递归）"

    step "observe" "对照：不加 -r 时两条递归路径缺席（递归的价值）"
    "$PY" dir_brute.py "$BASE" > "$OUT.norecur"
    local n_top
    n_top="$(grep -c '^\[+\] ' "$OUT.norecur" || true)"
    [ "$n_top" = "11" ] || die "预期 11 条顶层命中（无递归），实得 $n_top"
    if grep -q "admin/panel" "$OUT.norecur"; then die "未开递归时不应出现 /admin/panel"; fi
    if grep -q "api/status" "$OUT.norecur"; then die "未开递归时不应出现 /api/status"; fi
    ok "无递归只找到顶层 11 条；递归补上 /admin/panel 与 /api/status"

    step "observe" "软 404 降噪对比：关闭过滤后未知路径全员「命中」"
    "$PY" dir_brute.py "$BASE" --no-filter > "$OUT.nofilter"
    local total n_raw n_false
    total="$(grep -v -e '^#' -e '^[[:space:]]*$' configs/wordlist.txt | wc -l | tr -d ' ')"
    n_raw="$(grep -c '^\[+\] ' "$OUT.nofilter" || true)"
    [ "$n_raw" = "$total" ] || die "预期关闭降噪时 $total 个词全部命中，实得 $n_raw"
    n_false=$((total - n_top))
    echo "  关闭降噪：${n_raw}/${total} 个词全部「命中」（其中 ${n_false} 个是软 404 误报）"
    echo "  开启降噪：${n_top} 条真实命中，误报 0"
    ok "基线降噪把 ${n_false} 个软 404 误报清零"

    step "observe" "逐条复核：直接请求每条预置路径（独立于爆破器）"
    "$PY" - "$CONF" "$PORT" <<'PY' || die "逐条复核存在不一致（见上）"
import json, sys, urllib.error, urllib.request
conf = json.load(open(sys.argv[1], encoding="utf-8"))
bad = 0
for e in conf["paths"]:
    url = f"http://127.0.0.1:{sys.argv[2]}/{e['path']}"
    try:
        code = urllib.request.urlopen(url, timeout=3).status
    except urllib.error.HTTPError as ex:
        code = ex.code
    mark = "✅" if code == e["status"] else "❌"
    if code != e["status"]:
        bad += 1
    print(f"  {mark} /{e['path']:<18} {code}（预置 {e['status']}）")
sys.exit(1 if bad else 0)
PY
    ok "13/13 状态码与清单一致（爆破器报的每一条都真实存在）"

    step "observe" "DVWA 靶场对照（项目 12 就绪后自动生效）"
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${DVWA}/login.php" || true)" = "200" ]; then
        "$PY" dir_brute.py "$DVWA" > "$OUT.dvwa"
        local page
        for page in login.php instructions.php; do
            grep -q "/$page" "$OUT.dvwa" || die "DVWA 漏报 /$page"
        done
        # 未登录的 /security.php 与未知路径同形（302 → login.php、空体），会被降噪
        # 按设计滤掉——这正是过滤器的盲区；用 --no-filter 复核它真实存在。
        if grep -q "/security.php" "$OUT.dvwa"; then
            ok "DVWA 检出 /login.php、/security.php、/instructions.php"
        else
            "$PY" dir_brute.py "$DVWA" --no-filter > "$OUT.dvwa-nofilter"
            grep -q "/security.php" "$OUT.dvwa-nofilter" \
                || die "DVWA 漏报 /security.php（连 --no-filter 都没有）"
            echo "  ℹ️ /security.php 未登录时与未知路径完全同形（302 → login.php、空体）——"
            echo "     被软 404 降噪按设计丢弃；--no-filter 复核可见：过滤与漏报是一枚硬币。"
            ok "DVWA 检出 /login.php、/instructions.php；/security.php 为已知盲区（已复核）"
        fi
    else
        echo "  ℹ️  未检测到 DVWA（${DVWA} 不可达）：本机 Docker 未运行、Hub 直连不通，"
        echo "      项目 12 搭建靶场后重跑本步即可自动对照（与项目 2 用 dnsmasq 代替容器的原因相同）"
    fi
}

do_clean() {
    step "clean" "停止靶站，端口 ${PORT} 应关闭"
    if pid_is_ours; then                # 只杀确认是自己起的 lab_site.py 进程
        kill "$(cat "$PIDFILE")"
        local i
        for i in $(seq 1 20); do
            site_up || break
            sleep 0.2
        done
    fi
    rm -f "$PIDFILE"
    if site_up; then die "端口 ${PORT} 仍被占用（可能不是本脚本起的进程）"; fi
    ok "靶站已停止，环境复原"
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
