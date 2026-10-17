#!/usr/bin/env bash
# =============================================================================
# 12 · DVWA 靶场与渗透工作台 —— 起停 / 一键建库 / 登录与等级切换 / 改包重放
# 用法: ./dvwa.sh [apply|observe|clean|status]   (默认 all)
# 前置: Docker Desktop 运行中；源码从官方镜像抽取（不依赖 GitHub 连通性）
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"                      # 任意 cwd 运行都正确

PY="${PYTHON:-python3}"
PORT="${DVWA_PORT:-8612}"   # 避开 8080（开发服务器与 Burp 默认代理的重灾区）
ART="artifacts"                           # 源码/配置/cookie（.gitignore 已忽略）
SRC="$ART/dvwa"
COMPOSE=(docker compose -p hosec12 -f configs/docker-compose.yml)

step() { echo; echo "=====> [$1] $2"; }
ok()   { echo "  ✅ $*"; }
die()  { echo "  ❌ $*" >&2; exit 1; }

up() {  # 入口探针：login.php 返回 200
    [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
        "http://localhost:${PORT}/login.php" || true)" = "200" ]
}

ensure_source() {
    if [ -d "$SRC" ] && [ -f "$SRC/login.php" ]; then
        ok "DVWA 源码已存在：${SRC}（复用；删掉该目录可重新下载）"
        return 0
    fi
    step "apply" "获取 DVWA 源码（GitHub 直连不稳 → 走加速代理下载 tarball）"
    local url ok_dl=""
    for url in \
        "https://ghproxy.net/https://github.com/digininja/DVWA/archive/refs/heads/master.tar.gz" \
        "https://gh-proxy.com/https://github.com/digininja/DVWA/archive/refs/heads/master.tar.gz"; do
        if curl -sL --max-time 180 -o "$ART/dvwa.tar.gz" "$url"; then
            ok_dl="$url"; break
        fi
    done
    [ -n "$ok_dl" ] || die "源码下载失败：两个 GitHub 代理都不可达"
    tar -xzf "$ART/dvwa.tar.gz" -C "$ART"
    mv "$ART/DVWA-master" "$SRC"
    ok "源码就绪（DVWA master，来源：$(echo "$ok_dl" | cut -d/ -f3)）"
}

ensure_config() {
    [ -f "$ART/config.inc.php" ] && { ok "config.inc.php 已存在（复用）"; return 0; }
    # 从源码自带模板派生：只改数据库连接与默认安全等级（适配不同 DVWA 版本格式）
    "$PY" - "$SRC/config/config.inc.php.dist" "$ART/config.inc.php" <<'PY'
import re, sys
raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
pairs = {
    "db_server": "db", "db_database": "dvwa", "db_user": "root",
    "db_password": "p@ssw0rd", "default_security_level": "low",
}
for key, val in pairs.items():
    # 新版模板形如 $_DVWA[ 'db_server' ] = getenv('DB_SERVER') ?: '127.0.0.1'；
    # 整行替换为字面量；同时兼容老版 $db_server = '...' 写法
    pat = r"(?m)^\s*\$_DVWA\[\s*'%s'\s*\][^;]*;" % re.escape(key)
    raw, n = re.subn(pat, "$_DVWA[ '%s' ] = '%s';" % (key, val), raw)
    if n == 0:
        pat = r"(?m)^\s*\$\s*%s\s*=[^;]*;" % re.escape(key)
        raw, n = re.subn(pat, "$%s = '%s';" % (key, val), raw)
    assert n >= 1, f"未能在模板里定位字段 {key}"
open(sys.argv[2], "w", encoding="utf-8").write(raw)
print("[=] config.inc.php 已生成（5 个字段全部改写成功）")
PY
    ok "config.inc.php 就绪（db=db / 用户 root / 默认等级 low）"
}

do_apply() {
    step "apply" "环境检查与靶场栈启动"
    docker info >/dev/null 2>&1 || die "Docker daemon 未运行：先启动 Docker Desktop"
    mkdir -p "$ART"

    if up; then
        ok "靶场已在运行：http://localhost:${PORT}/login.php（复用）"
    else
        if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
            die "端口 ${PORT} 被其他进程占用：lsof -i :${PORT}（或 DVWA_PORT=8613 ./dvwa.sh）"
        fi
        ensure_source
        ensure_config
        chmod -R u+w "$SRC" 2>/dev/null || true
        chmod -R 777 "$SRC/hackable/uploads" 2>/dev/null || true
        step "apply" "构建并启动 compose 栈（首次约 1-3 分钟：装 PHP 扩展 + 建库）"
        "${COMPOSE[@]}" up -d --build
        local i
        for i in $(seq 1 90); do          # 就绪等待：最多 3 分钟，不裸 sleep
            up && break
            sleep 2
        done
        if ! up; then
            "${COMPOSE[@]}" logs --tail=20 web db || true
            die "靶场 3 分钟内未就绪（日志见上）"
        fi
        ok "入口就绪：http://localhost:${PORT}/login.php"
    fi

    step "apply" "初始化数据库（等价于浏览器打开 setup.php 点「Create / Reset Database」）"
    local tok
    curl -s -o "$ART/setup.html" -c "$ART/setup.jar" "http://localhost:${PORT}/setup.php"
    tok="$(sed -n "s/.*name='user_token' value='\([^']*\)'.*/\1/p" "$ART/setup.html" | head -1)"
    [ -n "$tok" ] || die "setup.php 未找到 CSRF token（DVWA 版本行为变化？）"
    curl -s -o /dev/null -b "$ART/setup.jar" -c "$ART/setup.jar" \
        --data-urlencode "create_db=Create / Reset Database" \
        --data "user_token=${tok}" \
        "http://localhost:${PORT}/setup.php"
    local tables
    tables="$(docker exec hosec12-db-1 mysql -uroot -pp@ssw0rd -N -e \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='dvwa'" 2>/dev/null || echo 0)"
    [ "${tables:-0}" -ge 2 ] || die "数据库初始化失败（dvwa 库里只有 ${tables} 张表）"
    ok "数据库已建好（dvwa 库 ${tables} 张表，含 users/guestbook）"
}

post_form() {  # $1=表单页面路径 $2=表单数据（自动补 CSRF token；DVWA 1.10+ 每页一次性 token）
    local page="$1" data="$2" tok
    curl -s -b "$jar" -c "$jar" "http://localhost:${PORT}${page}" > "$ART/form.html"
    tok="$(sed -n "s/.*name='user_token' value='\([^']*\)'.*/\1/p" "$ART/form.html" | head -1)"
    if [ -n "$tok" ]; then data="${data}&user_token=${tok}"; fi
    curl -s -o /dev/null -b "$jar" -c "$jar" -L --data "$data" \
        "http://localhost:${PORT}${page}"
}

do_observe() {
    local jar="$ART/cookies.txt" code
    rm -f "$jar"

    step "observe" "验收一：探活（就是验收清单里的那条命令）"
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${PORT}/login.php")"
    echo "  curl -s -o /dev/null -w \"%{http_code}\" http://localhost:${PORT}/login.php"
    echo "  → ${code}"
    [ "$code" = "200" ] || die "预期 200，实得 ${code}"
    ok "login.php 返回 200"

    step "observe" "验收二：登录 admin 并把安全等级切到 low（自动跟随 CSRF token）"
    post_form "/login.php" "username=admin&password=password&Login=Login"
    curl -s -b "$jar" "http://localhost:${PORT}/index.php" > "$ART/index.html"
    grep -qi "logout" "$ART/index.html" || die "登录失败（index 页没有登出入口）"
    ok "登录成功（admin / password）"

    post_form "/security.php" "security=low&seclev_submit=Submit"
    curl -s -b "$jar" "http://localhost:${PORT}/security.php" > "$ART/security.html"
    grep -qE 'value="low"[^>]*selected' "$ART/security.html" \
        || die "安全等级未切到 low"
    ok "安全等级已切换为 low（后续实验 13-18 的默认档位）"

    step "observe" "验收三：改包重放（Burp 拦截→改包→重放的手工版）"
    echo "  拦截：security.php 的表单提交里含 CSRF token（Burp 里能原样看到）"
    echo "  改包：把 security 从 low 改成 medium，重放同一请求"
    post_form "/security.php" "security=medium&seclev_submit=Submit"
    curl -s -b "$jar" "http://localhost:${PORT}/security.php" > "$ART/security2.html"
    grep -qE 'value="medium"[^>]*selected' "$ART/security2.html" \
        || die "改包重放未生效（等级没有变成 medium）"
    ok "重放成功：等级被改成 medium —— 服务器直接信任客户端提交（DVWA 的设计）"
    post_form "/security.php" "security=low&seclev_submit=Submit"
    ok "已复位回 low"

    if ls /Applications 2>/dev/null | grep -qi "burp"; then
        ok "检测到 Burp Suite 已安装：README 里有代理（默认 8080 即可）与拦截步骤"
    else
        echo "  ℹ️  未检测到 Burp Suite：brew install --cask burp-suite；"
        echo "      本步用 curl 复刻了「拦截→改包→重放」的完整工作流，Burp 步骤见 README"
    fi
}

do_status() {
    step "status" "查看栈状态"
    "${COMPOSE[@]}" ps || true
}

do_clean() {
    step "clean" "停止靶场栈并移除数据卷"
    "${COMPOSE[@]}" down -v
    sleep 0.5
    if up; then die "端口 ${PORT} 仍有响应（可能不是本栈起的进程）"; fi
    ok "容器与数据库卷已移除；源码保留在 ${SRC}（下次 apply 秒级起栈）"
}

main() {
    local target="${1:-all}"
    case "$target" in
        apply)   do_apply ;;
        observe) do_observe ;;
        clean)   do_clean ;;
        status)  do_status ;;
        all)     do_apply; do_observe; do_clean ;;
        *) echo "可用: apply | observe | clean | status | all" >&2; exit 1 ;;
    esac
}
main "$@"
