/* pwn-heap: a tiny "notes" service with a classic heap buffer
 * overflow that corrupts a function pointer stored in the SAME
 * heap allocation, right after the data it overflows out of.
 *
 * Each note is one malloc()'d struct:
 *
 *     struct note {
 *         char data[DATA_SIZE];   // attacker-controlled text
 *         void (*print)(struct note *); // called by the SHOW command
 *     };
 *
 * NEW copies attacker-supplied bytes into note->data using a length
 * taken directly from the client, bounded only by the (far too
 * generous) wire-protocol maximum -- NOT by sizeof(data). Supply more
 * than DATA_SIZE bytes and the extra bytes land on `print`, which
 * lives immediately afterward inside the same heap chunk. SHOW then
 * calls whatever `print` now holds.
 *
 * Protocol (plain text over TCP, one command per line):
 *   NEW <hex bytes>   - allocate a note, write hex-decoded bytes into it
 *   SHOW              - call the current note's print function
 *   QUIT              - close the connection
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DATA_SIZE 56
#define MAX_WIRE_BYTES 200  /* deliberately larger than DATA_SIZE */

struct note {
    char data[DATA_SIZE];
    void (*print)(struct note *);
};

static struct note *current = NULL;

void win(void) {
    char flag[256];
    FILE *f = fopen("/flag.txt", "r");
    if (!f) { puts("[server error] flag file missing"); return; }
    if (fgets(flag, sizeof(flag), f)) {
        printf("WIN: %s", flag);
    }
    fclose(f);
}

static void default_print(struct note *n) {
    printf("Note: %s\n", n->data);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *hex, size_t hexlen, unsigned char *out, size_t outmax) {
    if (hexlen % 2 != 0) return -1;
    size_t n = hexlen / 2;
    if (n > outmax) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return (int)n;
}

int main(void) {
    char line[MAX_WIRE_BYTES * 2 + 16];
    unsigned char payload[MAX_WIRE_BYTES];

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("pwn-heap notes service. Commands: NEW <hex>, SHOW, QUIT\n");
    fflush(stdout);

    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strcspn(line, "\r\n");
        line[len] = '\0';

        if (strncmp(line, "NEW ", 4) == 0) {
            int n = decode_hex(line + 4, len - 4, payload, sizeof(payload));
            if (n < 0) {
                printf("ERROR: bad hex\n");
                continue;
            }
            struct note *note = malloc(sizeof(struct note));
            if (!note) {
                printf("ERROR: allocation failed\n");
                continue;
            }
            note->print = default_print;
            memset(note->data, 0, DATA_SIZE);
            /* THE BUG: copies `n` bytes (attacker-controlled, up to
             * MAX_WIRE_BYTES) starting at note->data, with no check
             * against DATA_SIZE. n > DATA_SIZE overflows into the
             * `print` field that follows it in the same chunk. */
            memcpy(note->data, payload, (size_t)n);
            if (current) free(current);
            current = note;
            printf("OK\n");
        } else if (strcmp(line, "SHOW") == 0) {
            if (!current) {
                printf("ERROR: no note yet\n");
                continue;
            }
            current->print(current);
        } else if (strcmp(line, "QUIT") == 0) {
            break;
        } else {
            printf("ERROR: unknown command\n");
        }
        fflush(stdout);
    }
    return 0;
}
