#!/usr/bin/env bash
# =============================================================================
# 06 · pcap 流量分析报告生成器 —— 合成样本 / 分析报告 / tshark 交叉验证
# 用法: ./pcap_report.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install scapy；tshark 可选（README 的交叉验证一步，装上自动执行）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
ART="artifacts"                           # 生成目录（.gitignore 已忽略）
PCAP="$ART/demo-login.pcap"
REPORT="$ART/report.md"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "合成演示 pcap：回放一次明文 HTTP 登录会话（免 root）"
    "$PY" -c "import scapy" 2>/dev/null || die "缺少 scapy：pip3 install scapy"
    mkdir -p "$ART"
    "$PY" pcap_report.py make-sample "$PCAP" | tee "$ART/make.out"
    ok "样本已生成：${PCAP}（脚本合成——真实录制的 tcpdump 命令见 README）"
}

do_observe() {
    step "observe" "分析 pcap 并生成 Markdown 报告"
    if [ ! -f "$PCAP" ]; then                # 允许直接 observe：样本缺失就补合成
        mkdir -p "$ART"
        "$PY" pcap_report.py make-sample "$PCAP" >/dev/null
    fi
    "$PY" pcap_report.py report "$PCAP" -o "$REPORT" | tee "$ART/report.out"
    grep -q "S3cret123!" "$ART/report.out" || die "未提取到正确口令 S3cret123!"
    grep -q "wrongpass" "$ART/report.out" || die "未提取到失败尝试 wrongpass"
    ok "明文凭据提取 2/2（成功一次、失败一次都在报告里）"

    step "observe" "tshark 交叉验证：8 项统计逐项一致"
    if ! command -v tshark >/dev/null 2>&1; then
        echo "  ℹ️  未安装 tshark，跳过该步（brew install wireshark 后可补验）"
        return 0
    fi
    local key mine theirs
    for key in total tcp udp icmp arp dns http tls; do
        mine="$(sed -n "s/.* ${key}=\\([0-9]*\\).*/\\1/p" "$ART/report.out")"
        [ -n "$mine" ] || die "没能从 [STAT] 行解析出 ${key}"
        if [ "$key" = "total" ]; then
            theirs="$(tshark -r "$PCAP" -Y frame -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
        else
            theirs="$(tshark -r "$PCAP" -Y "$key" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')"
        fi
        [ "$mine" = "$theirs" ] || die "${key} 不一致：自研=${mine} tshark=${theirs}"
    done
    ok "total/tcp/udp/icmp/arp/dns/http/tls 八项与 tshark 完全一致"
}

do_clean() {
    step "clean" "清理生成物（artifacts/ 可随时重建）"
    rm -rf "$ART"
    ok "已清理，环境复原"
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
