// 25 · 栈溢出靶子：gets 无边界读入 + win() 后门函数（从不被调用）
// 编译（无保护，可被 ret2win）: gcc -O0 -fno-stack-protector -no-pie -z execstack -o vuln vuln.c
// 编译（开 canary 对照）:      gcc -O0 -fstack-protector-all -no-pie -o vuln-canary vuln.c
#include <stdio.h>
#include <stdlib.h>

char *gets(char *s); // 老 C 函数，无边界检查——本实验的“漏洞”本体

__attribute__((noinline)) void win(void) {
    system("cat /flag");
    exit(0); // win 是被劫持跳进来的：它自己的返回地址栈已不可信，打完旗标直接退
}

__attribute__((noinline)) void vuln(void) {
    char buf[64];
    puts("input:");
    gets(buf);
    puts("bye");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
