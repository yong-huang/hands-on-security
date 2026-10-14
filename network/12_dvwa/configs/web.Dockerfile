# 实验 12 · DVWA web 容器（本机离线可建版）
# 背景：本机到 Docker Hub / GitHub / Debian 源都不稳，但 alpine CDN 可达。
# 从 alpine:3.19 起底、apk 装 php82，用 PHP 内置服务器跑 DVWA。
# 网络不稳的现实对策：apk 包缓存挂载 + 6 次重试；gd 依赖链太重（aom 等）
# 且 DVWA 只把它列为「推荐」，故省略（setup 页会提示，功能不受影响）。
FROM alpine:3.19

RUN --mount=type=cache,target=/var/cache/apk,id=apk-fresh \
    sh -c 'set -e; for i in 1 2 3 4 5 6; do \
        apk add --cache-dir /var/cache/apk \
            php82 php82-mysqli php82-pdo_mysql php82-pdo \
            php82-mbstring php82-curl php82-session php82-iconv && exit 0; \
        echo "apk 第 $i 次失败，重试…"; sleep 3; \
    done; exit 1'

RUN printf 'allow_url_fopen = On\nallow_url_include = Off\ndisplay_errors = Off\ndate.timezone = Asia/Shanghai\nupload_max_filesize = 16M\n' \
        > /etc/php82/conf.d/99-dvwa.ini \
    && php82 -v | head -1

ENV PHP_CLI_SERVER_WORKERS=6
EXPOSE 80
CMD ["php82", "-S", "0.0.0.0:80", "-t", "/var/www/html"]
