#!/usr/bin/env bash
# =============================================================================
# 29 · 自建 mini-CTF —— flask 平台六关：套娃编码 / MD5 弱口令 / SQLite 注入 /
#      XSS 偷 cookie / 日志取证 / ELF crackme 逆向
# 用法: ./ctf_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: 宿主 python3（flask + requests）；node + puppeteer-core（XSS 机器人，
#       复用系列 node_modules）；Docker（编译 crackme）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
PORT="8930"
export PYTHONWARNINGS=ignore
NODE_MODULES="$HOME/.agents/skills/hands-on-series/scripts/node_modules"
export NODE_PATH="$NODE_MODULES"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "检查依赖 → 编译 crackme → 启动 flask 平台"
    command -v docker > /dev/null || die "缺少 docker"
    docker info > /dev/null 2>&1 || die "Docker 未运行（先启动 OrbStack / Docker Desktop）"
    "$PY" -c 'import flask, requests' 2>/dev/null || die "宿主缺 python3 依赖：pip3 install flask requests"
    command -v node > /dev/null || die "缺少 node（XSS 机器人）"
    [ -d "$NODE_MODULES/puppeteer-core" ] || die "缺少 puppeteer-core（系列 node_modules）"
    docker build -q -t hosec29-build configs/ > /dev/null
    mkdir -p "$ART"
    docker run --rm -v "$PWD/configs:/src:ro" -v "$PWD/$ART:/out" hosec29-build sh -c \
        'gcc -O0 -no-pie -o /out/crackme29 /src/crackme29.c'
    ok "crackme 已编译（aarch64 ELF：口令与 flag 均 0x5A XOR 混淆）"
    if [ -f "$ART/platform.pid" ]; then
        kill "$(cat "$ART/platform.pid")" 2>/dev/null || true
        rm -f "$ART/platform.pid"
    fi
    sleep 0.3
    rm -f "$ART/scoreboard.json"
    CTF_PORT="$PORT" CTF_STATE="$PWD/$ART/scoreboard.json" CTF_CRACKME="$PWD/$ART/crackme29" \
        nohup "$PY" ctf_platform.py > /tmp/hosec29-platform.log 2>&1 &
    echo $! > "$ART/platform.pid"
    disown 2>/dev/null || true  # 脱离作业表：kill 时不再打印带 PID 的通知（保可复现）
    "$PY" - <<'PYEOF' || die "平台未就绪（排查 /tmp/hosec29-platform.log）"
import sys, time, requests
for _ in range(30):
    try:
        requests.get("http://127.0.0.1:8930/", timeout=1)
        sys.exit(0)
    except Exception:
        time.sleep(0.3)
sys.exit(1)
PYEOF
    ok "平台已在 127.0.0.1:${PORT} 就绪（六题 / 判分 / 计分板；计分板从零开始）"
}

do_observe() {
    step "observe" "① 赛题清单：六关与分值"
    "$PY" - <<'PYEOF'
import requests
for c in requests.get("http://127.0.0.1:8930/api/list", timeout=5).json():
    print(f"  {c['id']} · {c['title']}（{c['points']} 分）")
PYEOF
    ok "六关齐备：编码 / 弱口令 / 注入 / XSS / 日志 / 逆向（总分 750）"

    step "observe" "② 六关全解并提交（官方解题器，逐题打印解题路径）"
    "$PY" solve_all.py --base "http://127.0.0.1:$PORT" --workdir "$ART" | tee "$ART/solve.out"
    [ "$(grep -c '✅ 正确' "$ART/solve.out")" = "6" ] || die "并非 6/6 判分通过"
    ok "6/6 全部解出且判分通过（验收：每题 flag 可解、可提交、被判对）"

    step "observe" "③ 计分板与判分正确性：得分/时间在案；重复与错旗被拒"
    "$PY" - <<'PYEOF' || die "计分板核验失败"
import requests
base = "http://127.0.0.1:8930"
sb = requests.get(f"{base}/scoreboard", timeout=5).json()
assert len(sb["solved"]) == 6 and sb["total"] == 750, sb
ts = [r["t"] for r in sb["solved"]]
assert ts == sorted(ts) and all(t > 0 for t in ts), ts
dup = requests.post(f"{base}/submit",
                    data={"cid": "c1", "flag": "HOSEC29{n3st3d_c0d1ng_l4y3rs}"}, timeout=5).json()
bad = requests.post(f"{base}/submit",
                    data={"cid": "c1", "flag": "HOSEC29{n0p3}"}, timeout=5).json()
assert dup["result"] == "already" and bad["result"] == "wrong", (dup, bad)
print("  ✓ 6/6 在案、总分 750、时间单调递增；重复提交→already、错旗→wrong")
PYEOF
    "$PY" - <<'PYEOF' | sed -E 's/T\+[0-9.]+s/T+Xs/g' | sed 's/^/  /'
import requests
print(requests.get("http://127.0.0.1:8930/scoreboard?format=text", timeout=5).text, end="")
PYEOF
    ok "计分板正确记录得分与时间（展示层归一化 T+Xs；scoreboard.json 保留原始值）"

    step "observe" "④ writeup 核验：六题解题过程就位"
    "$PY" - <<'PYEOF' || die "writeup 不齐"
from pathlib import Path
flags = {
    "01": "HOSEC29{n3st3d_c0d1ng_l4y3rs}", "02": "HOSEC29{w3ak_p4ssw0rd_cr4ck3d}",
    "03": "HOSEC29{sql1_1nj3ct10n_byp4ss}", "04": "HOSEC29{adm1n_c00k13_st0l3n}",
    "05": "HOSEC29{l0g_f0r3ns1cs_w1ns}", "06": "HOSEC29{r3v3rs3_0n3_st3p}",
}
files = sorted(Path("writeups").glob("*.md"))
assert len(files) == 6, files
for f in files:
    text = f.read_text(encoding="utf-8")
    key = f.name.split("_")[0]
    assert flags[key] in text and len(text) > 300, f.name
    print(f"  ✓ {f.name}（{len(text.encode('utf-8'))} 字节：思路 / 步骤 / 答案俱全）")
PYEOF
    ok "六篇 writeup 齐备且与平台答案一致（验收：每题附解题过程）"
}

do_clean() {
    step "clean" "停止平台并清理产物（crackme 重建秒级）"
    if [ -f "$ART/platform.pid" ]; then
        kill "$(cat "$ART/platform.pid")" 2>/dev/null || true
    fi
    rm -rf "$ART"
    ok "平台已停；构建镜像 hosec29-build 保留"
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
