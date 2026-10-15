/* 24 · 自编译 crackme：口令正确打印成功串，否则拒绝退出。
 * 教学点：口令与成功串都以明文躺在 .rodata——静态分析直接拿走。 */
#include <stdio.h>
#include <string.h>

static const char *SECRET = "hosec24-gate-key";
static const char *MSG_OK = "ACCESS GRANTED! flag=HOSEC24-STATIC-OK";
static const char *MSG_NO = "Access denied. Try again.";

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("usage: %s <password>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], SECRET) == 0) {
        puts(MSG_OK);
        return 0;
    }
    puts(MSG_NO);
    return 1;
}
