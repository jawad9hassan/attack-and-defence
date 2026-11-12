/* pwn-ret2libc: a classic stack buffer overflow, but this time there
 * is no gift win() function to jump to. Instead, libc itself is the
 * target -- and libc's load address is randomized by ASLR on every
 * run, so a hardcoded "jump to system()" address will not work twice
 * in a row. You need to leak a real, this-run address of a libc
 * function first, compute the libc base from it, and then compute
 * system()'s and "/bin/sh"'s addresses from that base before building
 * your real payload.
 *
 * The executable itself is built with -no-pie (its own code addresses
 * are fixed, exactly like pwn-baby/pwn-heap, to keep gadget-hunting
 * approachable), but it links against the system's normal, dynamically
 * loaded libc -- and libc's own ASLR is NOT disabled. That's the one
 * piece of real-world randomness this challenge is about.
 *
 * pop_rdi_ret (see gadgets.s) is a tiny, deliberately provided
 * one-instruction ROP gadget ("pop rdi; ret") so this challenge stays
 * about the ret2libc *technique* (leak -> compute -> redirect) rather
 * than turning into a gadget-hunting exercise. A real target usually
 * doesn't hand you a gadget this conveniently; you'd find an
 * equivalent "pop rdi; ret" sequence yourself with a tool like
 * ROPgadget or pwntools' ELF().search(), or build a longer chain out
 * of whatever gadgets the binary happens to contain.
 */
#include <stdio.h>
#include <string.h>

void pop_rdi_ret(void);

__attribute__((noinline))
void vulnerable(void) {
    char buf[64];
    printf("Give me input: ");
    fflush(stdout);
    gets(buf); /* no bounds checking at all -- the classic bug */
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    vulnerable();
    printf("Thanks, bye.\n");
    return 0;
}
