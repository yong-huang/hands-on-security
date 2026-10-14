#!/usr/bin/env bash
# =============================================================================
# 17 · 暴力破解与会话安全 —— 多线程爆破 / token+sleep+锁定 三道防线 / 会话固定检查
# 用法: ./brute_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 实验 12 的 DVWA 栈（本脚本自动拉起并校对时区）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
DVWA_COMPOSE="../12_dvwa/configs/docker-compose.yml"
MYSQL_PW="p@ssw0rd"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

tz_aligned() {  # db 与 web 是否同一时区（锁定计时依赖同区）
    local m p
    m="$(docker exec hosec12-db-1 mysql -uroot -p"$MYSQL_PW" -N -e 'SELECT date_format(now(), "%H");' 2>/dev/null)"
    p="$(docker exec hosec12-web-1 php82 -r 'echo date("H");' 2>/dev/null)"
    [ -n "$m" ] && [ "$m" = "$p" ]
}

do_apply() {
    step "apply" "拉起 DVWA + 校对时区 + 生成字典"
    mkdir -p "$ART"
    ../12_dvwa/dvwa.sh apply | tail -2

    if ! tz_aligned; then
        step "apply" "db 与 web 时区不一致：重放 compose 对齐（impossible 的锁定计时依赖同区）"
        docker compose -p hosec12 -f "$DVWA_COMPOSE" up -d > /dev/null 2>&1
        local i
        for i in $(seq 1 30); do tz_aligned && break; sleep 1; done
    fi
    tz_aligned || die "时区仍未对齐——检查 ../12_dvwa/configs/docker-compose.yml 的 default-time-zone"
    ok "时区已对齐：db 与 web 同一小时（锁定计时能正常工作）"

    "$PY" brute_lab.py gen-dict | tee "$ART/gen.out"
    grep -q "第 87 条" "$ART/gen.out" || die "字典生成异常"
    ok "字典就绪：dict-100.txt（第 87 条为目标口令）与 dict-impossible.txt（5 条，第 4 条正确）"
}

do_observe() {
    step "observe" "① low：无防护档——100 条字典多线程当场爆出"
    "$PY" brute_lab.py brute --level low --dict "$ART/dict-100.txt" --threads 4 \
        | tee "$ART/brute-low.out"
    grep -q "命中：字典第 87 条" "$ART/brute-low.out" || die "low 爆破未命中预期位置"
    ok "low：命中第 87 条 gordonb/abc123（耗时见上——验收标准 ① 要求 60 秒内）"

    step "observe" "② impossible：token + sleep + 锁定，五连试全部失败"
    set +e
    "$PY" brute_lab.py brute --level impossible --dict "$ART/dict-impossible.txt" --threads 1 \
        | tee "$ART/brute-imp.out"
    set -e
    grep -q "全部失败" "$ART/brute-imp.out" || die "impossible 竟然被爆出（锁定未生效）"
    echo "  ↳ 第 4 条就是正确口令——失败的不是口令，是账户已被锁定（第 3 次失败后锁 15 分钟）"
    echo "  ↳ 防护逐层拆解："
    echo "     · token：每个请求必须带上当轮页面里的 user_token——自动化被强制「每轮先读页面」"
    echo "     · sleep：失败惩罚 2-4 秒——100 条字典最少也是 200 秒起步，60 秒窗口装不下"
    echo "     · 锁定：3 次失败后 15 分钟拒绝一切登录——字典再全也打不进（gordonb 现在就是锁定态）"
    ok "impossible：5/5 全部失败——正确口令也进不去，这就是「限速 + 锁定」的威力"

    step "observe" "③ 会话固定检查：登录前后的 PHPSESSID 是否轮换"
    "$PY" brute_lab.py sess-check | tee "$ART/sess.out"
    grep -q "未轮换" "$ART/sess.out" || die "预期未轮换（会话固定面）未复现"
    ok "本栈登录不轮换会话 ID——存在会话固定面（修复：登录成功时重新生成会话）"

    step "observe" "④ 汇总：攻击侧 1 秒级命中；防御侧三层减速带；会话轮换缺位是独立问题"
    ok "三件事各自成立：爆破可行（低档）、防住有方（impossible 连正确口令都拦）、会话需加固"
}

do_clean() {
    step "clean" "清理生成物（靶场保持运行）"
    rm -rf "$ART"
    ok "产物已清；gordonb 的锁定态与靶场保留，要拆用 ../12_dvwa/dvwa.sh clean"
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
