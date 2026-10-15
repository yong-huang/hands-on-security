// 29 · 逆向关 crackme：口令与 flag 都以 0x5A XOR 混淆，strings 看不到明文
// 输对口令打印 flag；解法：静态定位 .rodata → 逐字节 XOR 0x5A 还原（详见 writeups/06）
#include <stdio.h>
#include <string.h>

static const unsigned char enc_pass[] = { 0x32, 0x35, 0x29, 0x3f, 0x39, 0x68, 0x63, 0x77, 0x29, 0x2e, 0x3b, 0x2e, 0x33, 0x39, 0x77, 0x31, 0x3f, 0x23 };
static const unsigned char enc_flag[] = { 0x12, 0x15, 0x09, 0x1f, 0x19, 0x68, 0x63, 0x21, 0x28, 0x69, 0x2c, 0x69, 0x28, 0x29, 0x69, 0x05, 0x6a, 0x34, 0x69, 0x05, 0x29, 0x2e, 0x69, 0x2a, 0x27 };

static void decode(const unsigned char *in, int n, char *out) {
    for (int i = 0; i < n; i++) out[i] = (char)(in[i] ^ 0x5A);
    out[n] = 0;
}

int main(void) {
    char buf[64], pass[64], flag[64];
    decode(enc_pass, sizeof enc_pass, pass);
    decode(enc_flag, sizeof enc_flag, flag);
    puts("password:");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (strcmp(buf, pass) != 0) { puts("wrong"); return 1; }
    printf("%s\n", flag);
    return 0;
}
