#!/usr/bin/env bash
# =============================================================================
# 28 · 容器安全审计器 —— docker inspect 危险配置 + trivy CVE 汇总 + 加固基线
# 用法: ./container_audit.sh [apply|observe|clean|all]   (默认 all)
# 前置: Docker（OrbStack / Docker Desktop）；trivy（brew install trivy）
# 说明: 漏洞库默认走国内可达镜像（南大 ghcr 代理 + AWS ECR 公共库），
#       可用 TRIVY_DB_REPOSITORY / TRIVY_JAVA_DB_REPOSITORY 环境变量覆盖
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
IMG_OLD="nginx:1.19"
C_BAD="hosec28-bad"
C_GOOD="hosec28-good"

export TRIVY_DB_REPOSITORY="${TRIVY_DB_REPOSITORY:-ghcr.nju.edu.cn/aquasecurity/trivy-db}"
export TRIVY_JAVA_DB_REPOSITORY="${TRIVY_JAVA_DB_REPOSITORY:-public.ecr.aws/aquasecurity/trivy-java-db}"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "检查 Docker / trivy → 备旧镜像与漏洞库 → 起「危险」与「加固」两容器"
    command -v docker > /dev/null || die "缺少 docker"
    docker info > /dev/null 2>&1 || die "Docker 未运行（先启动 OrbStack / Docker Desktop）"
    command -v trivy > /dev/null || die "缺少 trivy：brew install trivy"
    ok "trivy $(trivy --version | head -1 | awk '{print $2}')（漏洞库走国内镜像源，可经环境变量覆盖）"
    if ! docker image inspect "$IMG_OLD" > /dev/null 2>&1; then
        docker pull "$IMG_OLD" > /dev/null 2>&1 || {
            step "apply" "直连 Docker Hub 失败，改走 daocloud 镜像"
            docker pull "m.daocloud.io/docker.io/library/nginx:1.19" > /dev/null
            docker tag "m.daocloud.io/docker.io/library/nginx:1.19" "$IMG_OLD"
        }
    fi
    ok "旧镜像就位：${IMG_OLD}（2021 年 EOL，含大量已知 HIGH+ CVE 的对照靶）"
    trivy image --download-db-only --no-progress > /dev/null 2>&1 || die "漏洞库下载失败（网络）"
    trivy image --download-java-db-only --no-progress > /dev/null 2>&1 || true
    ok "漏洞库已就绪（缓存于 ~/.cache/trivy；后续扫描秒级）"
    docker rm -f "$C_BAD" "$C_GOOD" > /dev/null 2>&1 || true
    docker run -d --name "$C_BAD" --privileged --network host \
        -v /var/run/docker.sock:/var/run/docker.sock alpine:3.19 sleep infinity > /dev/null
    docker run -d --name "$C_GOOD" --read-only --cap-drop ALL \
        --security-opt no-new-privileges --user 1000:1000 alpine:3.19 sleep infinity > /dev/null
    sleep 1
    ok "两容器已起：bad = privileged + host 网络 + 挂 docker.sock；good = 全加固（--cap-drop ALL / 只读 / 非 root）"
}

do_observe() {
    step "observe" "① 危险容器：应检出「特权 / docker.sock / host 网络」三件套"
    mkdir -p "$ART"
    "$PY" audit.py container "$C_BAD" --json "$ART/bad.json" --report "$ART/bad.md" \
        | tee "$ART/bad.out"
    "$PY" - "$ART/bad.json" <<'PYEOF' || die "危险项漏检（三件套未全检出）"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
checks = {f["check"] for f in d["findings"]}
missing = {"privileged", "docker-sock", "host-network"} - checks
crit = sum(1 for f in d["findings"] if f["severity"] == "CRITICAL")
ok = not missing and crit >= 2 and "高危" in d["verdict"]
print(f"  ✓ 验收三件套全检出（privileged / docker-sock / host-network）；"
      f"CRITICAL {crit} 项、评分 {d['score']} → {d['verdict'].split('：')[0]}")
sys.exit(0 if ok else 1)
PYEOF
    ok "每条检出都带「为什么危险 + 修复动作」（完整报告：artifacts/bad.md）"

    step "observe" "② 加固对照：同款审计器对全加固容器应零检出（准入线）"
    "$PY" audit.py container "$C_GOOD" --json "$ART/good.json" | tee "$ART/good.out"
    "$PY" - "$ART/good.json" <<'PYEOF' || die "加固容器被误报"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
ok = len(d["findings"]) == 0 and "通过基线" in d["verdict"]
print(f"  ✓ 检出 {len(d['findings'])} 项、评分 {d['score']} → {d['verdict']}")
sys.exit(0 if ok else 1)
PYEOF
    ok "加固基线容器 0 告警——审计器先证明不误报，再谈抓危险"

    step "observe" "③ 旧镜像 CVE：trivy 扫 HIGH/CRITICAL 并汇总（验收 ≥1）"
    "$PY" audit.py image "$IMG_OLD" --json "$ART/cve.json" --report "$ART/cve.md" \
        | tee "$ART/cve.out"
    "$PY" - "$ART/cve.json" <<'PYEOF' || die "未汇总到 HIGH+ 漏洞"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
ok = (d["critical"] + d["high"]) >= 1 and len(d["top"]) >= 1
print(f"  ✓ 汇总 HIGH+ {d['critical'] + d['high']} 个"
      f"（CRITICAL {d['critical']} / HIGH {d['high']}），TOP 清单 {len(d['top'])} 条")
sys.exit(0 if ok else 1)
PYEOF
    ok "trivy 结果已汇总进报告与整改建议（完整报告：artifacts/cve.md）"
}

do_clean() {
    step "clean" "移除两容器并清理产物（镜像与漏洞库缓存保留，重跑秒级）"
    docker rm -f "$C_BAD" "$C_GOOD" > /dev/null 2>&1 || true
    rm -rf "$ART"
    ok "容器与产物已清；${IMG_OLD} 与 trivy 漏洞库缓存保留"
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
