#!/usr/bin/env bash
# =============================================================================
# 07 · 哈希识别与口令破解器 —— 样本生成 / 识别 / 字典+规则破解 / john 对照 / bcrypt 成本
# 用法: ./hash_cracker.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install bcrypt；john 可选（装上自动做对照，brew install john）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
ART="artifacts"                           # 生成目录（.gitignore 已忽略）
WORDLIST="$ART/wordlist.txt"
HASHES="$ART/all-hashes.txt"
BCRYPT="$ART/bcrypt.txt"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "生成演示目标（10 个弱口令 MD5 + 1 个 bcrypt cost=12）"
    "$PY" -c "import bcrypt" 2>/dev/null || die "缺少 bcrypt：pip3 install bcrypt"
    mkdir -p "$ART"
    "$PY" hash_cracker.py make-sample "$ART"
    ok "目标与字典已在 ${ART}/（哈希文件不含任何明文）"
}

do_observe() {
    step "observe" "哈希识别：按长度 / 前缀给出类型"
    "$PY" hash_cracker.py identify "$(head -1 "$ART/md5-raw.txt")" "$(cat "$BCRYPT")" \
        | tee "$ART/identify.out"
    grep -q "md5" "$ART/identify.out" || die "未识别出 MD5"
    grep -q "bcrypt.*cost=12" "$ART/identify.out" || die "未识别出 bcrypt(cost=12)"
    ok "MD5 与 bcrypt(cost=12) 均识别正确"

    step "observe" "字典攻击（无规则）：直出字典的 8 个应命中"
    "$PY" hash_cracker.py crack "$HASHES" -w "$WORDLIST" -t 8 | tee "$ART/crack-norules.out"
    grep -q "破解 8/10" "$ART/crack-norules.out" || die "无规则预期 8/10"
    ok "无规则 8/10——两个带变换的口令留给规则"

    step "observe" "字典攻击（-r 规则变换）：应 10/10"
    "$PY" hash_cracker.py crack "$HASHES" -w "$WORDLIST" -r -t 8 | tee "$ART/crack.out"
    grep -q "破解 10/10" "$ART/crack.out" || die "开规则后预期 10/10"
    grep -q "Password1" "$ART/crack.out" || die "缺 Password1（capitalize+尾数字规则）"
    grep -q "MONKEY" "$ART/crack.out" || die "缺 MONKEY（大写规则）"
    ok "10/10 全破（含 Password1、MONKEY 两个规则变形）"

    step "observe" "专业工具对照：同一字典还原 dragon / letmein"
    local tool_used="" john_bin="" cand
    for cand in "$(command -v john 2>/dev/null || true)" /opt/homebrew/opt/john-jumbo/bin/john; do
        if [ -n "$cand" ] && [ -x "$cand" ] && "$cand" --list=formats 2>/dev/null | grep -q "raw-md5"; then
            john_bin="$cand"
            break
        fi
    done
    if [ -n "$john_bin" ]; then
        # jumbo 版 john：pot 放进 artifacts（用 HOME 隔离，不碰 ~/.john）
        rm -rf "$ART/john-home"
        mkdir -p "$ART/john-home"
        HOME="$ART/john-home" "$john_bin" --format=raw-md5 --wordlist="$WORDLIST" \
            "$ART/md5-raw.txt" >/dev/null 2>&1 || true
        HOME="$ART/john-home" "$john_bin" --show --format=raw-md5 "$ART/md5-raw.txt" \
            > "$ART/tool-cross.out"
        cat "$ART/tool-cross.out"
        tool_used="john(jumbo)"
    elif command -v hashcat >/dev/null 2>&1; then
        rm -f "$ART/hashcat.pot"
        hashcat -m 0 -a 0 "$ART/md5-raw.txt" "$WORDLIST" \
            --potfile-path="$ART/hashcat.pot" -o "$ART/tool-cross.out" \
            --outfile-format 1,2 --quiet >/dev/null 2>&1 || true
        cat "$ART/tool-cross.out"
        tool_used="hashcat"
    fi
    if [ -n "$tool_used" ]; then
        grep -q "dragon" "$ART/tool-cross.out" || die "${tool_used} 未还原 dragon"
        grep -q "letmein" "$ART/tool-cross.out" || die "${tool_used} 未还原 letmein"
        ok "${tool_used} 与自研结果一致（dragon / letmein 均还原）"
    else
        echo "  ℹ️  john(需 jumbo 版)与 hashcat 都不可用，跳过对照（brew install john-jumbo）"
    fi

    step "observe" "bcrypt 成本实测：单次验证应 >100ms"
    "$PY" hash_cracker.py bench "$BCRYPT" | tee "$ART/bench.out"
    local ms
    ms="$("$PY" - "$ART/bench.out" <<'PY'
import re, sys
t = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"bcrypt.*?单次验证：([0-9.]+)ms", t)
print(m.group(1) if m else "0")
PY
)"
    "$PY" -c "import sys; sys.exit(0 if float('$ms') >= 100 else 1)" \
        || die "bcrypt 单次 ${ms}ms 未达 100ms（机器异常快？）"
    ok "bcrypt 单次 ${ms}ms ≥ 100ms：慢哈希把穷举成本抬高了四个数量级"
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
