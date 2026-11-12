#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Same idea as re-crackme: the real license key is hidden behind a
 * single-byte XOR, so a plain `strings` scan of the UNPACKED inner
 * binary doesn't show it directly. The point of THIS challenge isn't
 * this XOR step (you've done it before) -- it's getting to a point
 * where you can even run `strings`/`objdump` on something readable at
 * all. See the packer stub this gets wrapped in.
 */
static const unsigned char enc_key[] = {
    0x18, 0x03, 0x1d, 0x0c, 0x0e, 0x06, 0x40, 0x00, 0x08, 0x40, 0x03, 0x02,
    0x1a
};
#define KEY_LEN (sizeof(enc_key))
#define XOR_BYTE 0x6d

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

    puts("=== Packed License Validator ===");
    printf("Enter the license key: ");
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
