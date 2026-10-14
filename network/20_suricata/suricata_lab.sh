#!/usr/bin/env bash
# =============================================================================
# 20 · Suricata IDS 实战 —— 自定义规则 + 离线 pcap 检测 + jq 检索
# 用法: ./suricata_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: suricata（brew install suricata）；scapy（pip3 install scapy）
# 说明: macOS 无 inline/IPS 模式，全部走 -r 离线 pcap 分析
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
RULES="rules/local.rules"
NET='[192.0.2.0/24]'

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

run_suricata() {  # $1=pcap 文件名 $2=日志目录
    mkdir -p "$ART/$2"
    suricata --runmode single -r "$ART/pcaps/$1" -S "$RULES" -l "$ART/$2" \
        --set vars.address-groups.HOME_NET="$NET" \
        > "$ART/suricata-$2.run.log" 2>&1
    grep "read 1 file" "$ART/suricata-$2.run.log" | tail -1 | sed 's/^i: /[run] /'
}

do_apply() {
    step "apply" "检查依赖 + 规则语法自检 + 生成三段测试 pcap"
    command -v suricata > /dev/null || die "缺少 suricata（brew install suricata）"
    "$PY" -c "import scapy" 2>/dev/null || die "缺少 scapy（pip3 install scapy）"
    mkdir -p "$ART"
    suricata -T -S "$RULES" 2>&1 | grep -q "successfully loaded" \
        || die "规则语法自检未通过"
    ok "规则语法自检通过：$(grep -c '^alert' "$RULES") 条 alert 规则"
    "$PY" make_pcaps.py --outdir "$ART/pcaps" | tee "$ART/gen.out"
    grep -q "benign.pcap" "$ART/gen.out" || die "pcap 生成异常"
    ok "测试语料就绪（含负对照 benign.pcap）"
}

do_observe() {
    local n
    step "observe" "① SYN 扫描检出：100 端口 / 2 秒的扫描被规则 2000001 接住"
    run_suricata scan-syn.pcap log-scan
    n="$(wc -l < "$ART/log-scan/fast.log" | tr -d ' ')"
    [ "$n" -ge 1 ] || die "scan-syn.pcap 未产生告警"
    echo "[scan] fast.log 共 $n 条告警；第 1 条："
    head -1 "$ART/log-scan/fast.log" | sed 's/^/  /'
    grep -q "1:2000001" "$ART/log-scan/fast.log" || die "sid 2000001 未命中"
    ok "nmap SYN 扫描特征检出（阈值第 21 个 SYN 起每条后续 SYN 都告警）"

    step "observe" "② SQLi URI 检出：union select 请求被规则 2000002 接住"
    run_suricata sqli-union.pcap log-sqli
    sed 's/^/  /' "$ART/log-sqli/fast.log"
    grep -q "1:2000002" "$ART/log-sqli/fast.log" || die "sid 2000002 未命中"
    ok "URI 含 UNION SELECT 检出（HTTP 解析器直接给出 http.uri 层）"

    step "observe" "③ 负对照：正常请求零告警"
    run_suricata benign.pcap log-benign
    n="$(cat "$ART/log-benign/fast.log" 2>/dev/null | wc -l | tr -d ' ')"
    [ "$n" = "0" ] || die "负对照误报 $n 条"
    ok "benign.pcap 告警 0 条——没有误报才算检测器合格"

    step "observe" "④ jq 检索 eve.json：机读口径的告警事件"
    jq -c 'select(.event_type=="alert") | {sid: .alert.signature_id, sig: .alert.signature, src: .src_ip, dst: .dest_ip}' \
        "$ART/log-scan/eve.json" > "$ART/jq-scan.jsonl"
    jq -c 'select(.event_type=="alert") | {sid: .alert.signature_id, sig: .alert.signature, src: .src_ip, dst: .dest_ip}' \
        "$ART/log-sqli/eve.json" > "$ART/jq-sqli.jsonl"
    echo "[jq] scan 首条：$(head -1 "$ART/jq-scan.jsonl")"
    echo "[jq] sqli 首条：$(head -1 "$ART/jq-sqli.jsonl")"
    grep -q "2000001" "$ART/jq-scan.jsonl" || die "jq 未检索到 2000001"
    grep -q "2000002" "$ART/jq-sqli.jsonl" || die "jq 未检索到 2000002"
    ok "eve.json 两条告警均可被 jq 检索（验收 ②）"
}

do_clean() {
    step "clean" "清理生成物（pcap 与日志目录）"
    rm -rf "$ART"
    ok "产物已清；规则文件保留在 rules/local.rules"
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
