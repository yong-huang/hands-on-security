#!/usr/bin/env bash
# =============================================================================
# 11 · JWT 安全实验室 —— 三个靶（vuln/weak/strong）/ 三种攻击 / 正常路径对照
# 用法: ./jwt_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install PyJWT flask requests cryptography
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
BASE_PORT="${LAB_PORT:-8501}"             # 三个靶连号端口：base / +1 / +2
PORT_V="$BASE_PORT"; PORT_W=$((BASE_PORT + 1)); PORT_S=$((BASE_PORT + 2))
ART="artifacts"                           # RSA 密钥等生成物（.gitignore 已忽略）
WL="configs/wordlist.txt"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

up() {  # 靶站可达探针：无 token 访问 /admin 必得 401（服务活着就会给状态码）
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$1/admin" || true)" = "401" ]
}
wait_up() {
    local i
    for i in $(seq 1 20); do
        up "$1" && return 0
        sleep 0.2
    done
    return 1
}
pid_is_ours() {                           # $1=pidfile $2=命令特征
    [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null \
        && ps -p "$(cat "$1")" -o command= 2>/dev/null | grep -q "$2"
}
start_target() {                          # $1=名字 $2=模式 $3=端口
    local name="$1" mode="$2" port="$3"
    local pidfile="/tmp/hosec11-${name}.pid"
    if pid_is_ours "$pidfile" "serve ${mode}"; then
        ok "${name} 靶已在运行 (PID $(cat "$pidfile"))，直接复用"
        return 0
    fi
    rm -f "$pidfile"
    "$PY" jwt_lab.py serve "$mode" --port "$port" --keys "$ART" \
        > "/tmp/hosec11-${name}.log" 2>&1 &
    echo $! > "$pidfile"
    disown 2>/dev/null || true
    wait_up "$port" || { tail -3 "/tmp/hosec11-${name}.log" 2>/dev/null || true;
        die "${name} 靶 4 秒内未就绪（端口 ${port} 可能被占用）"; }
    ok "${name} 靶就绪：http://127.0.0.1:${port}"
}
stop_target() {                           # $1=名字 $2=模式
    local pidfile="/tmp/hosec11-$1.pid"
    if pid_is_ours "$pidfile" "serve $2"; then kill "$(cat "$pidfile")"; fi
    rm -f "$pidfile"
}

do_apply() {
    step "apply" "生成 RSA 密钥对并启动三个 JWT 靶（vuln / weak / strong）"
    "$PY" -c "import jwt, flask, requests, cryptography" 2>/dev/null \
        || die "缺少依赖：pip3 install PyJWT flask requests cryptography"
    mkdir -p "$ART"
    "$PY" jwt_lab.py keygen "$ART"
    start_target vuln vuln "$PORT_V"
    start_target weak weak "$PORT_W"
    start_target strong strong "$PORT_S"
}

do_observe() {
    step "observe" "攻击一：none 算法伪造 → 攻破信任 header 算法的靶"
    "$PY" jwt_lab.py attack none "http://127.0.0.1:$PORT_V" | tee "$ART/attack-none.out"
    grep -q "HTTP 200" "$ART/attack-none.out" || die "none 攻击未得手（vuln 靶应被攻破）"
    grep -q "JWT-ADMIN-AREA-OK" "$ART/attack-none.out" || die "未拿到 admin flag"
    ok "伪造签名段为空的 token，拿到 admin 响应（漏洞模式按 token 自称的算法验签）"

    step "observe" "攻击二：HS256 弱密钥字典爆破（离线验签，30 秒红线）"
    "$PY" jwt_lab.py attack brute "http://127.0.0.1:$PORT_W" -w "$WL" | tee "$ART/attack-brute.out"
    grep -q "命中：密钥 = secret" "$ART/attack-brute.out" || die "未爆破出弱密钥 secret"
    local secs
    secs="$(sed -n 's/.*耗时 \([0-9.]*\)s.*/\1/p' "$ART/attack-brute.out" | tail -1)"
    "$PY" -c "import sys; sys.exit(0 if float('${secs}') < 30 else 1)" \
        || die "爆破耗时 ${secs}s 超过 30 秒红线"
    ok "18 词字典命中 secret（耗时 ${secs}s）——弱密钥 6 字符纯小写，字典一击即中"

    step "observe" "对照：同一批攻击打在强靶（RS256）上——三种全部失败"
    "$PY" jwt_lab.py attack none "http://127.0.0.1:$PORT_S" > "$ART/strong-none.out" || true
    "$PY" jwt_lab.py attack confuse "http://127.0.0.1:$PORT_S" > "$ART/strong-confuse.out" || true
    "$PY" jwt_lab.py attack brute "http://127.0.0.1:$PORT_S" -w "$WL" > "$ART/strong-brute.out" || true
    grep -q "HTTP 401" "$ART/strong-none.out" || die "强靶被 none 攻破（不该发生）"
    grep -q "HTTP 401" "$ART/strong-confuse.out" || die "强靶被混淆攻击攻破（不该发生）"
    grep -q "未命中" "$ART/strong-brute.out" || die "强靶被字典命中（不该发生）"
    echo "  ---- none ----";    sed 's/^/  /' "$ART/strong-none.out"
    echo "  ---- confuse ----"; sed 's/^/  /' "$ART/strong-confuse.out"
    echo "  ---- brute ----";   sed 's/^/  /' "$ART/strong-brute.out"
    ok "强靶三连拒：固定算法白名单 + 非对称签名（没有可猜的共享密钥）"

    step "observe" "正常路径：alice 登录拿 token，访问 /admin 应为 403（角色不足）"
    local token code
    token="$(curl -s -X POST "http://127.0.0.1:$PORT_S/login" \
        -H 'Content-Type: application/json' \
        -d '{"username":"alice","password":"wonderland"}' \
        | "$PY" -c "import sys,json;print(json.load(sys.stdin)['token'])")"
    code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${token}" \
        "http://127.0.0.1:$PORT_S/admin")"
    [ "$code" = "403" ] || die "正常用户预期 403，实得 ${code}"
    ok "合法 token 也只能到 403——认证通过 ≠ 授权通过，角色要单独校验"
}

do_clean() {
    step "clean" "停止三个靶，清理密钥等生成物"
    stop_target vuln vuln
    stop_target weak weak
    stop_target strong strong
    sleep 0.3
    local p
    for p in "$PORT_V" "$PORT_W" "$PORT_S"; do
        if up "$p"; then die "端口 ${p} 仍在响应（可能不是本脚本起的进程）"; fi
    done
    rm -rf "$ART"
    ok "三靶已停、密钥已清（artifacts/ 可随时重建），环境复原"
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
