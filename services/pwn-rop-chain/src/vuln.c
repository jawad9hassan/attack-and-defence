/* pwn-rop-chain: a stack buffer overflow, same bug family as every
 * other pwn/* challenge here -- but this time there is no simple,
 * parameterless win() you can just jump to. win() takes THREE
 * arguments and actively checks them; getting the flag means
 * building a real multi-gadget ROP CHAIN that sets up rdi, rsi and
 * rdx with the exact expected values across two separate gadgets
 * (see gadgets.s) before finally jumping into win().
 *
 * Like pwn-ret2libc, the two gadgets you need (pop_rdi_ret and
 * pop_rsi_rdx_ret) are provided as named symbols so this challenge
 * stays about CHAINING gadgets together correctly -- not about
 * finding them. A real target wouldn't label them for you; you'd
 * find equivalent instruction sequences yourself with a tool like
 * ROPgadget or pwntools' ELF().search(), or by reading the
 * disassembly of whatever functions the binary already has.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void pop_rdi_ret(void);
void pop_rsi_rdx_ret(void);

#define EXPECT_A 0xdeadbeefUL
#define EXPECT_B 0xcafebabeUL
#define EXPECT_C 0x1337UL

void win(uint64_t a, uint64_t b, uint64_t c) {
    if (a != EXPECT_A || b != EXPECT_B || c != EXPECT_C) {
        printf("win() reached, but with the wrong arguments -- no flag.\n");
        return;
    }
    char flag[256];
    FILE *f = fopen("/flag.txt", "r");
    if (!f) { printf("[server error] flag file missing\n"); return; }
    if (fgets(flag, sizeof(flag), f)) {
        printf("WIN: %s", flag);
    }
    fclose(f);
}

__attribute__((noinline))
void vulnerable(void) {
    char buf[64];
    printf("Give me input: ");
    fflush(stdout);
    gets(buf); /* the classic unbounded read */
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    vulnerable();
    printf("Thanks, bye.\n");
    return 0;
}
