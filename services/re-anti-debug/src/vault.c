#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

/* The real vault key is obfuscated with a single-byte XOR, same idea
 * as re-crackme -- a plain `strings` scan alone won't show it.
 *
 * The NEW thing in this challenge: a classic anti-debugging self-check.
 * ptrace(PTRACE_TRACEME, ...) asks the kernel "let my own parent trace
 * me" -- and a process can only ever be traced by ONE tracer at a
 * time. If a debugger (gdb, strace, etc.) is ALREADY attached when
 * this runs, the call fails (returns -1), because the debugger is
 * already the tracer. This program uses exactly that failure as a
 * signal: "someone is trying to single-step through me" -- and reacts
 * by refusing to run the real check at all.
 *
 * This blocks the easy path of "just run it in gdb and read the key
 * out of memory/registers at runtime." It does NOT block pure static
 * analysis (reading bytes out of the binary file without executing
 * it), and it does NOT affect this service when it's reached normally
 * over the network (nothing is tracing it there), which is why the
 * remote /check still works completely normally for every real
 * connection.
 */
static const unsigned char enc_key[] = {
    0x32, 0x29, 0x2b, 0x28, 0x24, 0x2c, 0x6a, 0x33, 0x2f, 0x22, 0x6a, 0x31,
    0x26, 0x32, 0x2b, 0x33, 0x66, 0x66
};
#define KEY_LEN (sizeof(enc_key))
#define XOR_BYTE 0x47

void print_flag(void) {
    char buf[256];
    FILE *f = fopen("/flag.txt", "r");
    if (!f) {
        puts("[server error] flag file missing");
        exit(1);
    }
    if (fgets(buf, sizeof(buf), f)) {
        printf("%s", buf);
    }
    fclose(f);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    /* --- Anti-debug self-check --------------------------------------- */
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        puts("Debugger detected. Exiting.");
        return 1;
    }
    /* ------------------------------------------------------------------- */

    char guess[128];
    char real_key[KEY_LEN + 1];
    size_t i;

    for (i = 0; i < KEY_LEN; i++) {
        real_key[i] = (char)(enc_key[i] ^ XOR_BYTE);
    }
    real_key[KEY_LEN] = '\0';

    puts("=== Vault Access Terminal ===");
    printf("Enter the vault key: ");
    if (!fgets(guess, sizeof(guess), stdin)) {
        return 0;
    }
    guess[strcspn(guess, "\n")] = '\0';

    if (strcmp(guess, real_key) == 0) {
        puts("Access granted. Here is your flag:");
        print_flag();
    } else {
        puts("Access denied: invalid key.");
    }

    return 0;
}
