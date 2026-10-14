#!/usr/bin/env bash
# =============================================================================
# 22 · YARA 规则与恶意样本扫描器 —— 三规检出 / EICAR 必中 / 白名单降噪 / 万级性能
# 用法: ./yara_lab.sh [apply|observe|clean|all]   (默认 all)
# 前置: pip3 install yara-python
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ART="artifacts"
RULES="rules/local.yar"

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

do_apply() {
    step "apply" "检查依赖 + 生成 10 个自造样本与白名单"
    "$PY" -c "import yara" 2>/dev/null || die "缺少 yara-python（pip3 install yara-python）"
    mkdir -p "$ART"
    "$PY" make_samples.py --outdir "$ART" | tee "$ART/gen.out"
    local n
    n="$(ls "$ART/samples" | wc -l | tr -d ' ')"
    [ "$n" = "10" ] || die "样本数应为 10，实际 $n"
    ok "样本就绪：3 个含恶意特征 + 7 个正常（白名单示例 1 条同步生成）"
}

do_observe() {
    step "observe" "① 三规扫描：10 个样本 → 3/3 检出、7 个正常零误报"
    "$PY" yara_scan.py scan --path "$ART/samples" --rules "$RULES" \
        --json "$ART/scan.json" | tee "$ART/scan.out"
    "$PY" - "$ART/scan.json" <<'PYEOF' || die "检出结果与预期不符（漏报/误报见上）"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
hits = {(h["file"].rsplit("/", 1)[-1], h["rule"]) for h in d["hits"]}
want = {
    ("sample-01-eicar.txt", "EICAR_Test_File"),
    ("sample-02-downloader.sh", "Suspicious_Download_And_Execute"),
    ("sample-03-beacon.txt", "Hardcoded_IP_Endpoint"),
}
missing = want - hits
extra = hits - want
bad = bool(missing or extra or len(hits) != 3)
for x in sorted(missing):
    print("  漏报:", x)
for x in sorted(extra):
    print("  误报:", x)
sys.exit(1 if bad else 0)
PYEOF
    ok "3/3 恶意全检出、7 个正常零误报（验收 ①）"

    step "observe" "② EICAR 标准测试文件：必然命中"
    "$PY" yara_scan.py scan --path "$ART/samples/sample-01-eicar.txt" --rules "$RULES" \
        | tee "$ART/eicar.out"
    grep -q "EICAR_Test_File" "$ART/eicar.out" || die "EICAR 未命中"
    grep -q "命中 1 条" "$ART/eicar.out" || die "EICAR 命中数异常"
    ok "EICAR 命中（规则 / 偏移 / 命中串见上）——行业标准的无害测试串（验收 ②）"

    step "observe" "③ 白名单降噪：把已知测试件从报告里摘出去"
    "$PY" yara_scan.py scan --path "$ART/samples" --whitelist "$ART/whitelist.txt" \
        --json "$ART/scan-wl.json" | tee "$ART/scan-wl.out"
    "$PY" - "$ART/scan-wl.json" <<'PYEOF' || die "白名单降噪结果异常"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
sys.exit(0 if d["skipped"] == 1 and len(d["hits"]) == 2 else 1)
PYEOF
    ok "白名单跳过 1 个已知测试件：命中 3 → 2，其余不变"

    step "observe" "④ 万级文件性能：10000 个文件全量扫描"
    "$PY" yara_scan.py perf --count 10000 --dir "$ART/perf" --rules "$RULES" | tee "$ART/perf.out"
    grep -q "命中 0 条" "$ART/perf.out" || die "性能语料不应有命中"
    "$PY" - "$ART/perf.out" <<'PYEOF' || die "扫描耗时超过 30 秒验收线"
import re, sys
m = re.search(r"耗时 ([\d.]+)s", open(sys.argv[1], encoding="utf-8").read())
sys.exit(0 if m and float(m.group(1)) < 30 else 1)
PYEOF
    ok "10000 文件扫描耗时见上（验收线 30s，验收 ③）"
}

do_clean() {
    step "clean" "清理生成物（样本、性能语料与结果）"
    rm -rf "$ART"
    ok "产物已清；规则文件保留在 rules/local.yar"
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
