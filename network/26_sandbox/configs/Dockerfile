# 26 · 沙箱容器：ubuntu 22.04 + Python3（psutil 进程/网络快照 + watchdog 文件事件）
# 网络不稳时 apt 自动重试；构建一次即可复用
FROM ubuntu:22.04
RUN sh -c 'set -e; for i in 1 2 3; do \
        apt-get update -qq && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            python3 python3-psutil python3-watchdog && exit 0; \
        echo "apt 第 $i 次失败，重试…"; sleep 3; \
    done; exit 1' && rm -rf /var/lib/apt/lists/*
