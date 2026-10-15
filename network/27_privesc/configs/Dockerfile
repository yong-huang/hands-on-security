# 27 · 提权靶机：ubuntu 22.04 + sudo/cron/python3，构建期预埋 3 条提权路径
# 网络不稳时 apt 自动重试；构建一次即可复用
FROM ubuntu:22.04
RUN sh -c 'set -e; for i in 1 2 3; do \
        apt-get update -qq && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            sudo cron python3 && exit 0; \
        echo "apt 第 $i 次失败，重试…"; sleep 3; \
    done; exit 1' && rm -rf /var/lib/apt/lists/*
COPY plant_privesc.sh /plant_privesc.sh
RUN bash /plant_privesc.sh && rm /plant_privesc.sh
CMD ["cron", "-f"]
