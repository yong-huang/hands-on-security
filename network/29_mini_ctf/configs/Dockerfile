# 29 · crackme 编译容器：alpine + gcc（musl 工具链，产物为 aarch64 ELF）
FROM alpine:3.19
RUN sh -c 'set -e; for i in 1 2 3; do \
        apk add --no-cache gcc musl-dev && exit 0; \
        echo "apk 第 $i 次失败，重试…"; sleep 3; \
    done; exit 1'
