#!/usr/bin/env bash
# =============================================================================
# 23 · 应急响应靶场演练 —— 预埋 5 处后门的靶机 / 只读取证排查 / 基线零误报 / IR 报告
# 用法: ./ir_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: Docker（本机无 ubuntu:22.04 时自动经 daocloud 镜像拉取）；仅标准库
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
IMAGE="hosec23-target"
MIRROR="m.daocloud.io/docker.io/library/ubuntu:22.04"
C_TARGET="hosec23-target"
C_CLEAN="hosec23-clean"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

extract_fs() {  # $1=容器名 $2=目标目录：python tarfile 解包（macOS tar 会剥掉 SUID 位）
    rm -rf "$2"
    mkdir -p "$2"
    "$PY" - "$1" "$2" <<'PYEOF'
import io, subprocess, sys, tarfile
raw = subprocess.run(["docker", "export", sys.argv[1]], capture_output=True, check=True).stdout
tarfile.open(fileobj=io.BytesIO(raw)).extractall(sys.argv[2])
PYEOF
}

do_apply() {
    step "apply" "检查 Docker → 构建靶机镜像 → 导出「靶机 + 干净基线」两份快照"
    command -v docker > /dev/null || die "缺少 docker"
    docker info > /dev/null 2>&1 || die "Docker 未运行（先启动 OrbStack / Docker Desktop）"
    if ! docker image inspect ubuntu:22.04 > /dev/null 2>&1; then
        step "apply" "本机无 ubuntu:22.04：经 daocloud 镜像拉取"
        docker pull "$MIRROR" > /dev/null && docker tag "$MIRROR" ubuntu:22.04
    fi
    docker build -q -t "$IMAGE" configs/ > /dev/null
    ok "靶机镜像已构建（ubuntu:22.04 + 5 处预埋：cron/UID0/ssh key/隐藏 SUID/history）"
    docker rm -f "$C_TARGET" "$C_CLEAN" > /dev/null 2>&1 || true
    docker create --name "$C_TARGET" "$IMAGE" > /dev/null
    docker create --name "$C_CLEAN" ubuntu:22.04 sleep infinity > /dev/null
    mkdir -p "$ART"
    extract_fs "$C_TARGET" "$ART/target-fs"
    extract_fs "$C_CLEAN" "$ART/clean-fs"
    ok "两份只读快照已导出：artifacts/target-fs（预埋靶机）+ artifacts/clean-fs（基线）"
}

do_observe() {
    step "observe" "① 靶机排查：五路检查逐项取证（证据路径 + 片段 + mtime）"
    "$PY" ir_scan.py scan --root "$ART/target-fs" \
        --json "$ART/scan.json" --report "$ART/ir-report.md" | tee "$ART/scan.out"
    "$PY" - "$ART/scan.json" <<'PYEOF' || die "未达到 ≥4/5 检出（见上）"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
cats = {f["category"] for f in d["findings"]}
missing = {"计划任务", "账号", "SSH 授权键", "SUID 后门", "命令历史"} - cats
if missing:
    print("  漏检:", sorted(missing))
sys.exit(1 if missing or d["score"] < 100 else 0)
PYEOF
    ok "5/5 处后门全部检出、评分 120 → 高度疑似失陷（验收 ≥4/5）"

    step "observe" "② 干净基线对照：同样五路检查应零误报"
    "$PY" ir_scan.py scan --root "$ART/clean-fs" --json "$ART/scan-clean.json" \
        | tee "$ART/scan-clean.out"
    "$PY" - "$ART/scan-clean.json" <<'PYEOF' || die "基线出现误报（不合格的检测器）"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
sys.exit(0 if len(d["findings"]) == 0 else 1)
PYEOF
    ok "干净 ubuntu:22.04 基线 0 处异常——检测器先过准入线，再谈检出"

    step "observe" "③ IR 报告核验：证据路径齐全 + 时间线按 mtime 还原"
    [ -f "$ART/ir-report.md" ] || die "缺少 ir-report.md"
    local p
    for p in "/etc/cron.d/system-update" "/etc/passwd" "/root/.ssh/authorized_keys" \
             "/usr/local/bin/.sysmon" "/root/.bash_history"; do
        grep -q "· \`$p\`" "$ART/ir-report.md" || die "报告缺证据路径 $p"
    done
    grep -q "## 3. 发现时间线" "$ART/ir-report.md" || die "报告缺时间线节"
    "$PY" - "$ART/ir-report.md" <<'PYEOF' || die "时间线未按时间排序或条目数不对"
import re, sys
rows = []
for l in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r"\| (\d{4}-\d{2}-\d{2} [\d:]{8}) \|", l)
    if m:
        rows.append(m.group(1))
sys.exit(0 if rows == sorted(rows) and len(rows) == 5 else 1)
PYEOF
    echo "  ↳ 时间线（节选）："
    sed -n '/## 3\./,$p' "$ART/ir-report.md" | grep '^|' | head -7 | sed 's/^/    /'
    ok "报告四节齐全：五项证据路径在案，时间线 02:41→04:02（UTC）按序还原"
}

do_clean() {
    step "clean" "删除演练容器并清理快照（镜像保留，重跑秒级）"
    docker rm -f "$C_TARGET" "$C_CLEAN" > /dev/null 2>&1 || true
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
