#!/usr/bin/env bash
# =============================================================================
# 26 · 恶意行为监控沙箱 —— 三路采集（进程树 / 文件变更 / 网络外联）→ 评分 → 画像报告
# 用法: ./sandbox_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: Docker（首次构建 ubuntu + python3-psutil/watchdog 镜像）；仅标准库
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
IMAGE="hosec26-sandbox"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }
norm() { sed -E 's/T\+[0-9.]+s/T+Xs/g' "$1"; }

run_sample() {  # $1=样本名（不含 .py；json/报告按样本名落盘）
    docker run --rm -e SAMPLE="$1" -v "$PWD:/lab:ro" -v "$PWD/$ART:/work" "$IMAGE" bash -c '
        rm -rf /sandbox && mkdir -p /sandbox/victim
        for f in q1_report notes budget photo_list contacts; do
            printf "secret-%s\n" "$f" > /sandbox/victim/$f.txt
        done
        python3 /lab/monitor.py run --sample /lab/samples/$SAMPLE.py \
            --json /work/behavior-$SAMPLE.json --report /work/report-$SAMPLE.md'
}

do_apply() {
    step "apply" "检查 Docker → 构建沙箱镜像（ubuntu + psutil + watchdog）"
    command -v docker > /dev/null || die "缺少 docker"
    docker info > /dev/null 2>&1 || die "Docker 未运行（先启动 OrbStack / Docker Desktop）"
    docker build -q -t "$IMAGE" configs/ > /dev/null
    ok "沙箱镜像已构建（ubuntu 22.04 + python3-psutil + python3-watchdog）"
    ok "样本与监控器经只读挂载进入沙箱，靶目录每次运行现造——用完即弃"
}

do_observe() {
    step "observe" "① 恶意样本：批量加密 + 定时外联 → 三路采集 → 行为画像"
    mkdir -p "$ART"
    run_sample malicious | tee "$ART/malicious.out"
    "$PY" - "$ART/behavior-malicious.json" <<'PYEOF' || die "检出不足：类别 <4 或评分 <60"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
cats = {f["category"] for f in d["findings"]}
ok = len(cats) >= 4 and d["score"] >= 60 and "高度疑似" in d["verdict"]
print(f"  ✓ 检出 {len(cats)} 类（验收 ≥4）、评分 {d['score']}（≥60）、结论「{d['verdict']}」")
sys.exit(0 if ok else 1)
PYEOF
    echo "  ↳ 画像报告（展示层把相对时间归一化为 T+Xs；报告文件保留原始值）："
    sed -n '/## 1/,/## 3/p' <(norm "$ART/report-malicious.md") | grep -E '^- |^\| T' | sed 's/^/  /'
    norm "$ART/report-malicious.md" | grep -E '^- \*\*' | sed 's/^/  /'
    norm "$ART/report-malicious.md" | grep '总分' | sed 's/^/  /'
    ok "报告四节齐全：概览 / 时间线 / 明细 / 结论"

    step "observe" "② 良性对照：纯计算样本——同一套检测器应当零告警"
    run_sample benign | tee "$ART/benign.out"
    "$PY" - "$ART/behavior-benign.json" <<'PYEOF' || die "良性样本被误报"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
ok = len(d["findings"]) == 0 and d["score"] == 0 and "未见明显恶意" in d["verdict"]
print(f"  ✓ 检出 {len(d['findings'])} 类、评分 {d['score']}、结论「{d['verdict']}」")
sys.exit(0 if ok else 1)
PYEOF
    echo "  ↳ 报告结论：$(grep '总分' "$ART/report-benign.md")"
    ok "良性样本 0 告警——检测器先过准入线，再谈检出（与实验 23 同一纪律）"

    step "observe" "③ 报告核验：时间线有序 + 类别齐全 + 证据可回溯 + 四节完整"
    "$PY" - "$ART/report-malicious.md" <<'PYEOF' || die "报告核验不通过"
import re, sys
md = open(sys.argv[1], encoding="utf-8").read()
rows = re.findall(r"\| T\+([\d.]+)s \|", md)
cats = re.findall(r"- \*\*(.+?)\*\*（\+(\d+)", md)
paths = re.findall(r"/sandbox/[\w./-]+", md)
vals = [float(x) for x in rows]
# 展示口径：时间线按 0.1s 桶排序，桶内按规则序——校验同口径的单调性
mono = all(round(a, 1) <= round(b, 1) for a, b in zip(vals, vals[1:]))
ok = (len(rows) == len(cats) and len(rows) >= 4 and mono
      and len(paths) >= 5
      and all(s in md for s in ("## 1. 概览", "## 2. 行为时间线", "## 3. 检出项明细", "## 4. 评分与结论")))
print(f"  ✓ 时间线 {len(rows)} 行（0.1s 粒度有序）；检出 {len(cats)} 类；证据路径 {len(paths)} 处；四节齐全")
sys.exit(0 if ok else 1)
PYEOF
    ok "报告核验通过：每条检出都有时间线与可回溯证据（验收：报告含行为时间线 ✓）"
}

do_clean() {
    step "clean" "清理产物（沙箱为 --rm 一次性容器；镜像保留，重跑秒级）"
    rm -rf "$ART"
    ok "产物已清；沙箱镜像 ${IMAGE} 保留"
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
