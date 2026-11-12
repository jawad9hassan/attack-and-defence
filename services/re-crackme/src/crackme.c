#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The real license key is NOT stored in plain text -- it's obfuscated
 * with a single-byte XOR before being embedded here, specifically so a
 * plain `strings` scan of the binary won't show it directly. It's still
 * easily recoverable once you can read raw bytes out of the binary
 * (objdump, a hex editor, gdb, radare2 -- any of them work) and know
 * (or figure out) the XOR key.
 */
static const unsigned char enc_key[] = {
    0x32, 0x6e, 0x39, 0x31, 0x69, 0x28, 0x05, 0x29, 0x31, 0x6b, 0x36, 0x36, 0x20
};
#define KEY_LEN (sizeof(enc_key))
#define XOR_BYTE 0x5A

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

    char guess[128];
    char real_key[KEY_LEN + 1];
    size_t i;

    for (i = 0; i < KEY_LEN; i++) {
        real_key[i] = (char)(enc_key[i] ^ XOR_BYTE);
    }
    real_key[KEY_LEN] = '\0';

    puts("=== License Validator v1.0 ===");
    printf("Enter the license key: ");
    if (!fgets(guess, sizeof(guess), stdin)) {
        return 0;
    }
    guess[strcspn(guess, "\n")] = '\0';

    if (strcmp(guess, real_key) == 0) {
        puts("Access granted. Here is your flag:");
        print_flag();
    } else {
        puts("Access denied: invalid license key.");
    }

    return 0;
}
