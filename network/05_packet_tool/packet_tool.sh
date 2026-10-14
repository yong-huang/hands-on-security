#!/usr/bin/env bash
# =============================================================================
# 05 · 数据包构造与嗅探工具 —— 环境自检 / 构造演示 / ARP+ICMP 扫描 / 自收发抓包
# 用法: [sudo] ./packet_tool.sh [apply|observe|clean|all]   (默认 all)
#   完整流程需要 root（发送原始包 + BPF 抓包都是特权操作）：sudo ./packet_tool.sh
#   免 root 运行时自动跳过三个特权步骤并给出提示，构造演示仍可完成
# 前置: pip3 install scapy（脚本会自动找到带 scapy 的 python3）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

OUT="/tmp/hosec05"                        # 各步输出留档：断言与复跑都用它

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }
is_root() { [ "$(id -u)" = "0" ]; }

# sudo 的 PATH 可能不含 Homebrew，逐个候选挑「能 import scapy」的 python3
find_py() {
    local c
    for c in "${PYTHON:-}" "$(command -v python3 || true)" \
             /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        [ -n "$c" ] && [ -x "$c" ] && "$c" -c "import scapy" 2>/dev/null && { echo "$c"; return 0; }
    done
    return 1
}

do_apply() {
    step "apply" "环境自检（scapy / 权限 / 本网段 / 回环靶机）"
    local py
    py="$(find_py)" || die "找不到带 scapy 的 python3：pip3 install scapy"
    echo "  ℹ️  python3：$py"
    mkdir -p "$OUT"
    "$py" packet_tool.py info | tee "$OUT/info.txt"
    # 本实验没有常驻靶场：靶 = 本机回环（ICMP 常驻应答）+ 所在网段
    "/sbin/ping" -c 1 -t 1 127.0.0.1 >/dev/null 2>&1 \
        || die "回环 ping 失败（抓包演示的靶机不可用）"
    ok "回环靶机 127.0.0.1 应答正常（抓包演示将对着它发 ping）"
    if is_root; then
        ok "已具备 root：ARP 扫描 / ping sweep / 抓包三步会真实执行"
    else
        echo "  ℹ️  当前是普通用户：三个特权步骤会跳过；完整流程用 sudo ./packet_tool.sh"
    fi
}

do_observe() {
    local py n
    py="$(find_py)" || die "找不到带 scapy 的 python3：pip3 install scapy"

    step "observe" "① 构造演示：ARP / ICMP / TCP（免 root）"
    "$py" packet_tool.py craft | tee "$OUT/craft.txt"
    grep -q "构造演示完成" "$OUT/craft.txt" || die "craft 未完成"
    ok "三个包都通过「构造 → 序列化 → 反解析」"

    step "observe" "② ARP 扫描本网段（需要 root）"
    if is_root; then
        "$py" packet_tool.py arp-scan | tee "$OUT/arp.txt"
        grep -q "← 网关" "$OUT/arp.txt" || die "ARP 扫描未列出网关（网络环境有变化？）"
        grep -q "本机 MAC" "$OUT/arp.txt" || die "ARP 输出缺本机 MAC 行"
        ok "ARP 扫描列出网关与本机 MAC"
    else
        echo "  ⏭  跳过：需要 root（原始套接字）——完整验证用 sudo ./packet_tool.sh"
    fi

    step "observe" "③ ICMP 扫描本网段（需要 root）"
    if is_root; then
        "$py" packet_tool.py ping-sweep | tee "$OUT/ping.txt"
        grep -q "^\[PING\]" "$OUT/ping.txt" || die "ping sweep 没有任何主机应答（检查 ICMP 是否被网络拦截）"
        ok "ping sweep 列出在线主机（回包带 ← 网关 / ← 本机 标记）"
    else
        echo "  ⏭  跳过：需要 root（原始套接字）"
    fi

    step "observe" "④ 抓包：边抓边发，捕获自己发的 ping（需要 root）"
    if is_root; then
        "$py" packet_tool.py sniff | tee "$OUT/sniff.txt"
        n="$(grep -c '^\[SNIFF\]' "$OUT/sniff.txt" || true)"
        [ "$n" -ge 10 ] || die "只捕获到 ${n} 个包（阈值 10）"
        grep -q "echo-reply" "$OUT/sniff.txt" || die "未捕获到 echo-reply"
        ok "捕获 ${n} 个 ICMP 包（含 echo-reply）"
    else
        echo "  ⏭  跳过：需要 root（/dev/bpf 抓包权限）"
    fi

    if ! is_root; then
        echo
        echo "  ℹ️  本次为免 root 运行：只完成了①；②③④ 的输出留档在 sudo 运行后生成于 ${OUT}/"
    fi
}

do_clean() {
    step "clean" "残留检查（本实验无常驻进程）"
    if pgrep -f "packet_tool.py" >/dev/null 2>&1; then
        die "仍有 packet_tool.py 进程（可能是被中断的嗅探）：pgrep -fl packet_tool.py 查看"
    fi
    ok "无遗留进程；留档输出在 ${OUT}/（纯文本，可随时删）"
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
