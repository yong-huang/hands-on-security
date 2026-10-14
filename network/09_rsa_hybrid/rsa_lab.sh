#!/usr/bin/env bash
# =============================================================================
# 09 · RSA 原理与混合加密 —— 教材版样例 / OAEP / 1MB 信封加密与双层篡改检测
# 用法: ./rsa_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install cryptography（仓库根 load_resources.sh 清单已覆盖）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
ART="artifacts"                           # 生成目录（.gitignore 已忽略）

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "造 1MB 样本并做信封加密（AES-GCM 加密数据 + RSA-OAEP 封装密钥）"
    "$PY" -c "import cryptography" 2>/dev/null \
        || die "缺少 cryptography：pip3 install cryptography"
    mkdir -p "$ART"
    "$PY" rsa_lab.py envelope make "$ART" | tee "$ART/envelope-make.out"
    ok "envelope.bin 就绪（头 + 256B 封装密钥 + nonce + 密文段）"
}

do_observe() {
    step "observe" "教材版 RSA：p=61, q=53 经典样例逐步复算"
    "$PY" rsa_lab.py toy | tee "$ART/toy.out"
    grep -q "与教材一致（d=2753、c=2790、m'=65）：是" "$ART/toy.out" \
        || die "教材样例不一致"
    grep -q "同态性" "$ART/toy.out" || die "缺同态性演示"
    ok "私钥 d=2753、密文 c=2790、解密回 65——与教材逐项一致"

    step "observe" "真实 RSA-OAEP：随机填充让密文不再可预测"
    "$PY" rsa_lab.py oaep --out "$ART" | tee "$ART/oaep.out"
    grep -q "解密还原：是" "$ART/oaep.out" || die "OAEP 解密失败"
    grep -q "两次加密密文相同：否" "$ART/oaep.out" || die "OAEP 应随机化"
    ok "解密正常且两次密文不同——比对攻击失效"

    step "observe" "解封信封：sha256 应一致，两处篡改应各被拦下"
    "$PY" rsa_lab.py envelope open "$ART" | tee "$ART/envelope-open.out"
    grep -q "sha256 与原文一致：是" "$ART/envelope-open.out" || die "完整性失败：sha256 不一致"
    grep -q "数据段改 1 字节 → InvalidTag" "$ART/envelope-open.out" || die "数据段篡改未被检测"
    grep -q "封装密钥改 1 字节 → OAEP 解封失败" "$ART/envelope-open.out" || die "密钥段篡改未被检测"
    ok "还原一致；数据段与密钥段的 1 字节篡改分别被 GCM/OAEP 拦下"
}

do_clean() {
    step "clean" "清理生成物（artifacts/ 含临时密钥与样本，可随时重建）"
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
