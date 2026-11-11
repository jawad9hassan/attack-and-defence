#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* This function is never called directly by main().
 * It exists only so an attacker can redirect control flow into it
 * by overwriting the saved return address on the stack. */
void win(void) {
    char flag[128];
    FILE *f = fopen("/flag.txt", "r");
    if (!f) {
        puts("[server error] flag file missing");
        exit(1);
    }
    if (fgets(flag, sizeof(flag), f)) {
        printf("Congratulations! Here is your flag:\n%s\n", flag);
    }
    fclose(f);
    exit(0);
}

void vulnerable_echo(void) {
    char name[64]; /* small fixed-size stack buffer */

    printf("What's your name, traveler? ");
    fflush(stdout);

    /* VULNERABLE: gets() performs no bounds checking at all.
     * A long enough input overflows `name` and can overwrite
     * the saved return address on the stack. */
    gets(name);

    printf("Nice to meet you, %s!\n", name);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("=== Baby Overflow Service v1.0 ===");
    puts("This friendly service just wants to know your name.");

    vulnerable_echo();

    puts("Goodbye!");
    return 0;
}
