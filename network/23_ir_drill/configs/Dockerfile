# 23 · IR 演练靶机镜像：ubuntu 22.04 + 构建期预埋 5 处后门
# 说明：只做「文件级」预埋（不需要真的跑 sshd/cron 守护进程）——
#       排查脚本取证的对象就是这些文件与其 mtime。
FROM ubuntu:22.04
COPY plant_backdoors.sh /plant_backdoors.sh
RUN bash /plant_backdoors.sh && rm /plant_backdoors.sh
CMD ["sleep", "infinity"]
