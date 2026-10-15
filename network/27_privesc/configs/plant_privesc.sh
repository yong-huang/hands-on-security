#!/bin/bash
# 27 · 靶机预埋（构建期以 root 执行）：一名低权用户 + 三条真实世界常见的提权路径
set -euo pipefail

# 低权用户（无需密码登录——实验经 docker exec -u 进入）
useradd -m -s /bin/bash lowuser

# —— 路径①：SUID find 副本（GTFOBins：find -exec /bin/sh -p 保留 euid=0） ——
cp /usr/bin/find /usr/local/bin/findroot
chown root:root /usr/local/bin/findroot
chmod 4755 /usr/local/bin/findroot

# —— 路径②：sudo NOPASSWD 误配（awk 可 system() 逃逸，等于给了 root 壳） ——
cat > /etc/sudoers.d/backup-ops <<'EOF'
lowuser ALL=(root) NOPASSWD: /usr/bin/awk
EOF
chmod 440 /etc/sudoers.d/backup-ops

# —— 路径③：cron PATH 劫持（root 班车每分钟发车，PATH 先查低权用户目录） ——
mkdir -p /opt/backup /var/backups
printf 'important data\n' > /opt/backup/data.txt
cat > /usr/local/bin/daily-backup <<'EOF'
#!/bin/sh
tar czf /var/backups/daily.tgz /opt/backup
EOF
chmod 755 /usr/local/bin/daily-backup
cat > /etc/cron.d/daily-backup <<'EOF'
PATH=/home/lowuser/bin:/usr/bin:/bin
* * * * * root daily-backup
EOF
chmod 644 /etc/cron.d/daily-backup

chown -R lowuser:lowuser /home/lowuser
echo "[plant] 三条提权路径已预埋（SUID find 副本 / NOPASSWD awk / cron PATH 劫持）"
