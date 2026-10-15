#!/usr/bin/env bash
# =============================================================================
# 30 · 个人安全工具箱整合 —— sectool CLI（五合一）+ 一键冒烟三连
# 用法: ./toolbox_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 宿主 python3（requests + dnspython）；dnsmasq（冒烟靶，brew install）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "检查依赖：五件前置工具目录 + 宿主依赖"
    "$PY" -c 'import requests, dns' 2>/dev/null || die "缺依赖：pip3 install requests dnspython"
    local lab
    for lab in 01_tcp_port_scanner 02_dns_enum 03_dir_brute 07_hash_crack 19_log_audit; do
        [ -d "../$lab" ] || die "缺少前置实验目录 $lab"
    done
    "$PY" sectool.py --help > /dev/null || die "sectool 无法运行"
    ok "sectool 可运行；五件工具目录齐备（01 / 02 / 03 / 07 / 19）"
    ok "退出码约定：0 完成无发现 / 1 完成有发现 / 2 参数错 / 3 运行环境错"
}

do_observe() {
    step "observe" "① 根帮助：五个子命令一览（验收：--help 完整）"
    "$PY" sectool.py --help
    ok "五子命令齐备：scan-port / enum-dns / dir-brute / crack-hash / log-audit"

    step "observe" "② 一键冒烟（第 1/3 轮，完整输出：起最小靶 → 五项逐一验证）"
    mkdir -p "$ART"
    ./smoke_test.sh | tee "$ART/smoke-1.out"
    grep -q '通过 6 / 失败 0' "$ART/smoke-1.out" || die "第 1 轮冒烟有红项"
    ok "第 1/3 轮全绿：6 通过 / 0 失败"

    step "observe" "③ 连跑第 2、3 轮（--quiet：只看结论行）"
    local i line
    for i in 2 3; do
        line=$(./smoke_test.sh --quiet | tail -1)
        echo "  第 $i/3 轮：$line"
        case "$line" in
            *"通过 6 / 失败 0"*) ;;
            *) die "第 $i 轮冒烟有红项：$line" ;;
        esac
    done
    ok "冒烟测试连跑 3 次全绿（验收达成：一键冒烟连跑 3 次不红）"
}

do_clean() {
    step "clean" "清理冒烟夹具（最小靶进程由冒烟脚本自行回收）"
    rm -rf "$ART"
    ok "产物已清；系列五个工具与 sectool 本体原样保留"
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
