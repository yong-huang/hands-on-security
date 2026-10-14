#!/usr/bin/env bash
# =============================================================================
# load_resources.sh —— hands-on-security 环境体检（所有实验的公共前置）
#
# 用法:
#   bash scripts/load_resources.sh          # 体检：Python 依赖 / brew 工具 / Docker
#   bash scripts/load_resources.sh pip      # 安装缺失的 Python 依赖（清华镜像）
#   bash scripts/load_resources.sh brew     # 打印缺失 CLI 工具的安装命令
#
# 为什么需要它: 30 个实验共用一批 Python 包与 CLI 工具，每个实验开工前
# 10 秒确认，比跑到一半才发现缺包省时间；Docker 类实验（12 起）需 daemon 在线。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
PIP_MIRROR="${PIP_MIRROR:-https://pypi.tuna.tsinghua.edu.cn/simple}"

# Python 依赖：import 名:pip 包名
PIP_PKGS="dns:dnspython requests:requests cryptography:cryptography PyJWT:PyJWT bcrypt:bcrypt scapy:scapy yara:yara-python flask:flask PIL:pillow dpkt:dpkt pwn:pwntools"
# CLI 工具：名称:用途说明（说明不含空格）
BREW_TOOLS="nmap:端口对照 dnsmasq:DNS靶场 sqlmap:SQL注入 john:口令破解 hashcat:GPU破解 gobuster:目录爆破 suricata:IDS zeek:流量分析 trivy:镜像漏扫"

missing_pip=""
for pair in $PIP_PKGS; do
    mod="${pair%%:*}"; pkg="${pair##*:}"
    if ! "$PY" -c "import $mod" >/dev/null 2>&1; then
        missing_pip="$missing_pip $pkg"
        echo "  ❌ pip 缺失: $pkg (import $mod)"
    else
        echo "  ✅ pip: $pkg"
    fi
done

missing_brew=""
for pair in $BREW_TOOLS; do
    tool="${pair%%:*}"; why="${pair##*:}"
    if command -v "$tool" >/dev/null 2>&1 || [ -x "/opt/homebrew/opt/$tool/sbin/$tool" ]; then
        echo "  ✅ CLI: $tool ($why)"
    else
        missing_brew="$missing_brew $tool"
        echo "  ⬜ CLI 缺失: $tool ($why)"
    fi
done

if docker info >/dev/null 2>&1; then
    echo "  ✅ Docker daemon 在线（容器类实验可开工）"
else
    echo "  ⬜ Docker daemon 未运行（实验 12 起的靶场需要：启动 Docker Desktop / OrbStack）"
fi

case "${1:-check}" in
    check)
        [ -z "$missing_pip$missing_brew" ] && echo "环境就绪：全部依赖可用" || {
            echo
            echo "补齐方式：bash scripts/load_resources.sh pip   # 安装 Python 包"
            echo "          bash scripts/load_resources.sh brew  # 查看 brew 安装命令"
        }
        ;;
    pip)
        [ -z "$missing_pip" ] && { echo "Python 依赖已齐全"; exit 0; }
        echo "安装:$missing_pip"
        # shellcheck disable=SC2086
        "$PY" -m pip install -i "$PIP_MIRROR" $missing_pip
        ;;
    brew)
        [ -z "$missing_brew" ] && { echo "CLI 工具已齐全"; exit 0; }
        echo "brew install$missing_brew"
        ;;
    *)
        echo "可用: check | pip | brew" >&2; exit 1 ;;
esac
