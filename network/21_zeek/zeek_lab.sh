#!/usr/bin/env bash
# =============================================================================
# 21 · Zeek 流量分析 —— 离线重放产出日志 / C2 心跳检测 / UA 对账 / DGA 疑似
# 用法: ./zeek_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: zeek（brew install zeek）；scapy（pip3 install scapy）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
HTTP="$ART/zeek-logs/http.log"
DNSL="$ART/zeek-logs/dns.log"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "检查依赖 + 生成 C2 心跳 pcap + zeek 离线重放产出日志"
    command -v zeek > /dev/null || die "缺少 zeek（brew install zeek）"
    "$PY" -c "import scapy" 2>/dev/null || die "缺少 scapy（pip3 install scapy）"
    mkdir -p "$ART/zeek-logs"
    "$PY" make_c2_pcap.py --outdir "$ART/pcaps" | tee "$ART/gen.out"
    grep -q "c2-beacon.pcap" "$ART/gen.out" || die "pcap 生成异常"
    ( cd "$ART/zeek-logs" && zeek -r ../pcaps/c2-beacon.pcap ) > "$ART/zeek-run.log" 2>&1
    local f
    for f in conn.log dns.log http.log; do
        [ -s "$ART/zeek-logs/$f" ] || die "zeek 未产出 $f"
    done
    ok "zeek 日志就绪：conn / dns / http（http $(grep -vc '^#' "$HTTP") 条请求）"
}

do_observe() {
    step "observe" "① C2 心跳检测：按（源IP+域名）聚合，算间隔均值与标准差"
    "$PY" zeek_lab.py beacon --http "$HTTP" | tee "$ART/beacon.out"
    grep -q "beacon.cdn-analytics.net" "$ART/beacon.out" || die "未标出 beacon 域名"
    grep -q "平均间隔 30" "$ART/beacon.out" || die "未识别出 30 秒周期"
    "$PY" - "$ART/beacon.out" <<'PYEOF' || die "标准差未满足 <2s（验收①）"
import re, sys
m = re.search(r"标准差 ([\d.]+)s", open(sys.argv[1], encoding="utf-8").read())
raise SystemExit(0 if m and float(m.group(1)) < 2 else 1)
PYEOF
    ok "beacon 域名标出：30s 周期、标准差 <2s（验收 ①）"

    step "observe" "② UA Top5 对账：工具统计与 awk 手工统计逐条一致"
    "$PY" zeek_lab.py ua --http "$HTTP" --top 5 > "$ART/ua-tool.txt"
    local col
    col="$(awk -F'\t' '/^#fields/{for(i=2;i<=NF;i++) if($i=="user_agent"){print i-1; exit}}' "$HTTP")"
    awk -F'\t' -v c="$col" '!/^#/ && $c!="-" {print $c}' "$HTTP" \
        | sort | uniq -c | sort -rn | head -5 \
        | awk '{v=$1; $1=""; sub(/^ /,""); print v" "$0}' > "$ART/ua-awk.txt"
    if ! diff "$ART/ua-tool.txt" "$ART/ua-awk.txt" > /dev/null; then
        diff "$ART/ua-tool.txt" "$ART/ua-awk.txt" | head -5
        die "UA Top5 与 awk 不一致"
    fi
    echo "  ↳ 前 2 行：$(head -1 "$ART/ua-tool.txt" | cut -c1-60) … / $(sed -n 2p "$ART/ua-tool.txt" | cut -c1-40) …"
    ok "UA Top5 与 awk 手工统计逐条一致（验收 ②）"

    step "observe" "③ DGA 疑似：长标签 + 含数字 + 元音稀少的查询"
    "$PY" zeek_lab.py dga --dns "$DNSL" | tee "$ART/dga.out"
    grep -q "xj3kq9wzmv7p.net" "$ART/dga.out" || die "未标出随机域名"
    if grep -q "api.example.net" "$ART/dga.out"; then
        die "正常域名被误报"
    fi
    ok "随机域名标出、正常域名零误报"

    step "observe" "④ 分析报告：beacon / UA / DGA 汇总为 Markdown"
    "$PY" zeek_lab.py report --http "$HTTP" --dns "$DNSL" --out "$ART/zeek-report.md"
    local secs
    secs="$(grep -c '^## ' "$ART/zeek-report.md")"
    [ "$secs" = "4" ] || die "报告应有 4 节，实际 $secs"
    grep -q "beacon.cdn-analytics.net" "$ART/zeek-report.md" || die "报告缺主嫌疑"
    ok "报告就位：结论 / 心跳 / UA / DGA 四节（artifacts/zeek-report.md）"
}

do_clean() {
    step "clean" "清理生成物（pcap、zeek 日志与报告）"
    rm -rf "$ART"
    ok "产物已清；工具与脚本保留"
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
