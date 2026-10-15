# 24 · 编译/对照容器：alpine + gcc（musl 工具链）+ binutils（readelf / objdump / strings）
# 只做交叉编译与工具对照；网络不稳时 apk 自动重试
FROM alpine:3.19
RUN sh -c 'set -e; for i in 1 2 3; do \
        apk add --no-cache gcc musl-dev binutils && exit 0; \
        echo "apk 第 $i 次失败，重试…"; sleep 3; \
    done; exit 1'
