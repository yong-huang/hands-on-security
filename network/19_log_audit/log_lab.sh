#!/usr/bin/env bash
# =============================================================================
# 19 · 日志审计与爆破检测器 —— 合成日志 / 滑动窗口 / 规则引擎 / 实战日志检出
# 用法: ./log_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 实验 12 的 DVWA 栈（仅第 ③ 步捕实战日志用）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "拉起 DVWA + 生成 1000 条合成日志"
    mkdir -p "$ART"
    ../12_dvwa/dvwa.sh apply | tail -2
    "$PY" log_audit.py gen | tee "$ART/gen.out"
    local total
    total="$(cat "$ART/auth-synth.log" "$ART/access-synth.log" | wc -l | tr -d ' ')"
    [ "$total" = "1000" ] || die "合成日志应为 1000 行，实际 $total"
    ok "日志就绪：auth 600 + access 400（植入与负对照见上行）"
}

do_observe() {
    local hits
    step "observe" "① 合成日志审计：检出植入的爆破 IP 与规则命中"
    "$PY" log_audit.py audit --auth "$ART/auth-synth.log" --access "$ART/access-synth.log" \
        --report "$ART/audit-report.md" | tee "$ART/audit.out"
    hits="$(grep -c "来源 203.0.113.66" "$ART/audit.out" || true)"
    [ "$hits" -ge 3 ] || die "植入 IP 规则命中数应 ≥3，实际 $hits"
    grep -q "\[R1\]" "$ART/audit.out" || die "爆破规则 R1 未命中"
    if grep -q "198.51.100.23" "$ART/audit.out"; then
        die "负对照（8 次散落失败）被误报"
    fi
    ok "植入 IP 命中 $hits 条规则（验收 ≥3）；负对照零误报"

    step "observe" "② Top10 对账：工具统计与 awk 手工统计逐条一致"
    "$PY" log_audit.py stats --access "$ART/access-synth.log" > "$ART/stats-tool.txt"
    awk '{print $1}' "$ART/access-synth.log" | sort | uniq -c | sort -rn | head -10 \
        | awk '{print $1" "$2}' > "$ART/stats-awk.txt"
    if ! diff "$ART/stats-tool.txt" "$ART/stats-awk.txt" > /dev/null; then
        diff "$ART/stats-tool.txt" "$ART/stats-awk.txt" | head -5
        die "Top10 与 awk 不一致"
    fi
    echo "  ↳ 前 3 名：$(head -3 "$ART/stats-tool.txt" | tr '\n' ' ')"
    ok "Top10 与 awk 手工统计逐条一致（验收 ②）"

    step "observe" "③ 实战日志：对 DVWA 发真实攻击请求，从容器日志检出"
    local t0
    sleep 2                      # 等上一波流量落定，日志窗口只框住 probe
    t0="$(date +%s)"
    "$PY" log_audit.py probe | tee "$ART/probe.out"
    sleep 1
    docker logs --since "$t0" hosec12-web-1 > "$ART/web-access.log" 2>&1
    "$PY" log_audit.py audit --access "$ART/web-access.log" | tee "$ART/web-audit.out"
    grep -q "\[R3\]" "$ART/web-audit.out" || die "SQL 注入特征未检出"
    grep -q "UNION+SELECT" "$ART/web-audit.out" || die "注入 URI 特征未命中"
    ok "真实注入流量被检出（验收 ③）：SQLi / 路径穿越 / XSS 三条规则命中"

    step "observe" "④ Markdown 审计报告核验"
    [ -f "$ART/audit-report.md" ] || die "缺少 audit-report.md"
    local secs
    secs="$(grep -c '^## ' "$ART/audit-report.md")"
    [ "$secs" = "4" ] || die "报告应有 4 个小节，实际 $secs"
    grep -q "203.0.113.66" "$ART/audit-report.md" || die "报告缺可疑 IP"
    grep -q "建议动作" "$ART/audit-report.md" || die "报告缺建议动作节"
    ok "报告就位：结论摘要 / 规则命中 / Top10 / 建议动作 四节齐全"
}

do_clean() {
    step "clean" "清理生成物（靶场保持运行）"
    rm -rf "$ART"
    ok "产物已清；靶场留着，要拆用 ../12_dvwa/dvwa.sh clean"
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
