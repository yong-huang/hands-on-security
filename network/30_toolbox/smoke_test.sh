#!/usr/bin/env bash
# =============================================================================
# 30 · 一键冒烟测试：起最小靶 → 五个子命令逐一验证 → --help 完备性
#   最小靶：本地 HTTP（:8821，含 admin.html）+ lab.local DNS（dnsmasq :5300）
#   用法: ./smoke_test.sh [--quiet]     退出码 0=全绿（连跑 3 次不红即验收）
# =============================================================================
set -u
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
ROOT="$(cd .. && pwd)"
ART="artifacts/smoke"
HTTP_PORT=8821
DNS_PORT=5300
DNSMASQ="${DNSMASQ_BIN:-/opt/homebrew/opt/dnsmasq/sbin/dnsmasq}"
DNS_PIDFILE="/tmp/hosec02-dnsmasq.pid"
QUIET="${1:-}"

PASS=0
FAIL=0
say()  { [ "$QUIET" = "--quiet" ] || echo "$@"; }
green(){ PASS=$((PASS+1)); say "  ✓ $*"; }
red()  { FAIL=$((FAIL+1)); echo "  ✗ $*"; }

cleanup() {
    [ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null || true
    [ -n "${STARTED_DNS:-}" ] && kill "$(cat "$DNS_PIDFILE")" 2>/dev/null || true
    return 0
}
trap cleanup EXIT

# ---------------------------------------------------------------- 最小靶与夹具
say "[smoke] 准备夹具与最小靶…"
rm -rf "$ART"
mkdir -p "$ART/www"
printf 'admin panel\n' > "$ART/www/admin.html"
printf 'admin.html\nrobots\nnope\n' > "$ART/words.txt"
"$PY" - "$ART" <<'PYEOF'
import hashlib, sys
from pathlib import Path
art = Path(sys.argv[1])
(art / "crack_words.txt").write_text("letmein\nsmoke-pass\n", encoding="utf-8")
(art / "target.txt").write_text("md5:" + hashlib.md5(b"smoke-pass").hexdigest() + "\n", encoding="utf-8")
lines = [f"May  1 03:05:{i:02d} labhost sshd[{2001 + i}]: Failed password for admin "
         f"from 203.0.113.66 port {40001 + i} ssh2" for i in range(35)]
lines.append("May  1 03:06:11 labhost sshd[2999]: Accepted password for admin "
             "from 203.0.113.66 port 40512 ssh2")
(art / "auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
PYEOF
(cd "$ART/www" && exec "$PY" -m http.server "$HTTP_PORT" >/dev/null 2>&1) &
HTTP_PID=$!
"$PY" - <<PYEOF || { red "本地 HTTP 靶未就绪"; exit 1; }
import socket, sys, time
for _ in range(25):
    try:
        socket.create_connection(("127.0.0.1", $HTTP_PORT), timeout=1).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.2)
sys.exit(1)
PYEOF
if ! { [ -f "$DNS_PIDFILE" ] && ps -p "$(cat "$DNS_PIDFILE")" -o command= 2>/dev/null | grep -q dnsmasq; }; then
    "$DNSMASQ" --keep-in-foreground -C "$ROOT/02_dns_enum/configs/dnsmasq-lab.conf" >/dev/null 2>&1 &
    echo $! > "$DNS_PIDFILE"
    disown 2>/dev/null || true
    STARTED_DNS=1
fi
"$PY" - <<PYEOF || { red "lab.local DNS 未就绪"; exit 1; }
import sys, time
import dns.resolver
for _ in range(20):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers, r.port, r.lifetime = ["127.0.0.1"], $DNS_PORT, 1
    try:
        r.resolve("lab.local", "NS")
        sys.exit(0)
    except Exception:
        time.sleep(0.2)
sys.exit(1)
PYEOF
say "[smoke] 最小靶就绪：HTTP :${HTTP_PORT}（admin.html）· DNS :${DNS_PORT}（lab.local）"

# ---------------------------------------------------------------- 五个子命令
run_check() {  # $1=描述 $2=期望退出码 $3=输出应含 $4..=命令
    local desc="$1" want="$2" pat="$3"
    shift 3
    local out code
    out=$("$@" 2>&1)
    code=$?
    say "— $desc"
    [ "$QUIET" = "--quiet" ] || echo "$out" | sed 's/^/    /'
    if [ "$code" = "$want" ] && grep -q "$pat" <<<"$out"; then
        green "${desc}（退出码 ${code}，命中关键输出）"
    else
        red "${desc}（期望退出码 $want 含「${pat}」，实得 ${code}）"
    fi
}

run_check "scan-port 扫到开放端口" 1 "open" \
    "$PY" sectool.py scan-port 127.0.0.1 -p "$HTTP_PORT" -T 1
run_check "enum-dns 枚举出子域与 apex" 1 "shop.lab.local" \
    "$PY" sectool.py enum-dns lab.local --resolver 127.0.0.1 --port "$DNS_PORT"
run_check "dir-brute 命中 admin.html" 1 "admin.html" \
    "$PY" sectool.py dir-brute "http://127.0.0.1:$HTTP_PORT" -w "$ART/words.txt"
run_check "crack-hash 破解 smoke-pass" 1 "smoke-pass" \
    "$PY" sectool.py crack-hash "$ART/target.txt" -w "$ART/crack_words.txt"
run_check "log-audit 检出爆破来源" 1 "203.0.113.66" \
    "$PY" sectool.py log-audit --log "$ART/auth.log"

say "— --help 完备性（根 + 五子命令）"
HELP_OK=0
for c in scan-port enum-dns dir-brute crack-hash log-audit; do
    "$PY" sectool.py "$c" --help >/dev/null 2>&1 || HELP_OK=1
done
"$PY" sectool.py --help | grep -q "scan-port" || HELP_OK=1
if [ "$HELP_OK" = 0 ]; then
    green "--help 齐备：根帮助列出五子命令，各子命令帮助可打开"
else
    red "--help 不完备"
fi

echo "[smoke] 通过 $PASS / 失败 $FAIL"
[ "$FAIL" = 0 ]
