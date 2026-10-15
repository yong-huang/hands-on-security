# 25 · 靶场容器：ubuntu 22.04 + gcc（glibc——canary 命中会打出教科书级提示）
#        + gdb（偏移定位）+ socat（把靶子暴露成 TCP 服务）
# 网络不稳时 apt 自动重试；构建一次即可复用
FROM ubuntu:22.04
RUN sh -c 'set -e; for i in 1 2 3; do \
        apt-get update -qq && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            gcc libc6-dev gdb socat binutils && exit 0; \
        echo "apt 第 $i 次失败，重试…"; sleep 3; \
    done; exit 1' && rm -rf /var/lib/apt/lists/*
