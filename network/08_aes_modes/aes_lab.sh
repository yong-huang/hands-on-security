#!/usr/bin/env bash
# =============================================================================
# 08 · 对称加密实验室 —— 企鹅图加密对照（ECB vs CBC）/ IV 随机性 / GCM 篡改检测
# 用法: ./aes_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install cryptography pillow（两者都在仓库根 load_resources.sh 清单里）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
ART="artifacts"                           # 生成目录（.gitignore 已忽略）
PENGUIN="$ART/penguin"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "画一只企鹅（大面积同色区域，专为 ECB 演示定制）"
    "$PY" -c "import cryptography, PIL" 2>/dev/null \
        || die "缺少依赖：pip3 install cryptography pillow"
    mkdir -p "$ART"
    "$PY" aes_lab.py make-image "$PENGUIN"
    "$PY" aes_lab.py keyinfo 2>/dev/null || true
    ok "素材就绪：${PENGUIN}.bmp / ${PENGUIN}.png"
}

do_observe() {
    step "observe" "ECB vs CBC：同一张图，两种模式的密文长相"
    "$PY" aes_lab.py modes "${PENGUIN}.bmp" "$ART" | tee "$ART/modes.out"
    grep -q "密文重复块 0" "$ART/modes.out" || die "CBC 密文出现重复块（不该发生）"
    local rep_ecb
    rep_ecb="$(sed -n 's/^\[ECB\] 密文重复块 \([0-9]*\).*/\1/p' "$ART/modes.out")"
    [ -n "$rep_ecb" ] && [ "$rep_ecb" -ge 10 ] || die "ECB 重复块 ${rep_ecb}（预期 ≥10）"
    [ -f "$ART/ecb.png" ] && [ -f "$ART/cbc.png" ] || die "对照图未生成"
    ok "ECB 重复块 ${rep_ecb} 个（轮廓泄漏） / CBC 0 个（噪声）；图在 ${ART}/"

    step "observe" "IV 随机性：ECB 确定性 vs CBC 不可复现"
    "$PY" aes_lab.py randomness | tee "$ART/randomness.out"
    grep -q "密文一致：是" "$ART/randomness.out" || die "ECB 应确定性"
    grep -q "密文一致：否" "$ART/randomness.out" || die "CBC 两次密文应不同"
    ok "ECB 两次一致、CBC 两次不同——随机 IV 的作用"

    step "observe" "GCM 认证：只改 1 个字节密文，解密必被拒"
    "$PY" aes_lab.py gcm | tee "$ART/gcm.out"
    grep -q "InvalidTag" "$ART/gcm.out" || die "篡改未被检测"
    grep -q "正常解密：通过" "$ART/gcm.out" || die "正常路径解密失败"
    ok "篡改检测成立（InvalidTag）；正常解密不受影响"
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
