#!/usr/bin/env bash
# =============================================================================
# 27 · Linux 提权攻防 —— 低权视角扫描 / 手工 find 对照 / 三路利用拿 root
# 用法: ./privesc_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: Docker（首次 apt 构建靶机镜像约 1-2 分钟）；cron 班车每 60 秒一班，观察期会等车
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
IMAGE="hosec27-target"
C_TARGET="hosec27-target"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "检查 Docker → 构建预埋靶机 → 启动（cron 常驻发车）"
    command -v docker > /dev/null || die "缺少 docker"
    docker info > /dev/null 2>&1 || die "Docker 未运行（先启动 OrbStack / Docker Desktop）"
    docker build -q -t "$IMAGE" configs/ > /dev/null
    ok "靶机镜像已构建（ubuntu 22.04 + sudo/cron/python3，构建期预埋 3 条提权路径）"
    mkdir -p "$ART"
    docker rm -f "$C_TARGET" > /dev/null 2>&1 || true
    docker run -d --name "$C_TARGET" -h "$C_TARGET" \
        -v "$PWD:/lab:ro" -v "$PWD/$ART:/work" "$IMAGE" > /dev/null
    sleep 1
    ok "靶机已启动：cron 班车每分钟发车；主机名固定（sudo 输出可逐字对账）"
}

do_observe() {
    step "observe" "① 低权视角扫描：SUID 偏差 / NOPASSWD / cron 可劫持 / 可写敏感文件"
    docker exec -u lowuser "$C_TARGET" python3 /lab/privesc_scan.py --json /work/scan.json \
        | tee "$ART/scan.out"
    "$PY" - "$ART/scan.json" <<'PYEOF' || die "扫描器未按预期检出三路风险"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
f = d["findings"]
ok = (len(f["suid"]) == 1 and f["suid"][0]["path"] == "/usr/local/bin/findroot"
      and len(f["sudo"]) == 1 and f["sudo"][0]["command"] == "/usr/bin/awk"
      and len(f["cron"]) == 1 and not f["writable"])
print("  ✓ 检出：白名单外 SUID 1（findroot）/ NOPASSWD 1（awk）/ cron 可劫持 1（daily-backup）")
sys.exit(0 if ok else 1)
PYEOF
    ok "三条预埋路径全部命中，无多余误报（验收：检出与预埋一致）"

    step "observe" "② 手工对照：find / -perm -4000 与扫描器清单逐项比对"
    docker exec -u lowuser "$C_TARGET" sh -c \
        'find / -xdev -perm -4000 -type f 2>/dev/null | sort' > "$ART/find-suid.txt"
    sed 's/^/  ↳ /' "$ART/find-suid.txt"
    "$PY" - "$ART/scan.json" "$ART/find-suid.txt" <<'PYEOF' || die "扫描器 SUID 清单与手工 find 不一致"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
scan = sorted(s["path"] for s in d["suid"] if s["suid"])
find = sorted(l.strip() for l in open(sys.argv[2]) if l.strip())
ok = scan == find
print(f"  ✓ 两份清单完全一致：共 {len(scan)} 个 SUID（含 1 个白名单外偏差）")
sys.exit(0 if ok else 1)
PYEOF
    ok "检测脚本输出与手工排查结果一致（验收：与 find 对得上才算数）"

    step "observe" "③ 利用演示：三条路径逐一拿到 root（cron 需等下一班车，最长约 1 分钟）"
    docker exec -u lowuser "$C_TARGET" bash /lab/exploit_demo.sh | tee "$ART/exploit.out"
    local wins
    wins=$(grep -c 'id -u => 0' "$ART/exploit.out" || true)
    [ "$wins" -ge 3 ] || die "三条路径未全部拿到 root（得手 $wins 次）"
    ok "3/3 路径全部拿到 root（id -u=0；另留 rootbash 副本一枚）——验收要求 ≥2/3"
}

do_clean() {
    step "clean" "移除靶机容器并清理产物（镜像保留，重跑秒级）"
    docker rm -f "$C_TARGET" > /dev/null 2>&1 || true
    rm -rf "$ART"
    ok "容器与产物已清；靶机镜像 ${IMAGE} 保留"
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
