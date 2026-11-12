#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* This flag starts closed. There is no code path in main() that ever
 * sets it to anything other than 0 ... unless an attacker finds one. */
int unlocked = 0;

void print_flag(void) {
    char flag[256];
    FILE *f = fopen("/flag.txt", "r");
    if (!f) {
        puts("[server error] flag file missing");
        exit(1);
    }
    if (fgets(flag, sizeof(flag), f)) {
        printf("Access granted. Here is your flag:\n%s\n", flag);
    }
    fclose(f);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    char name[64];
    char feedback[256];

    puts("=== Diagnostic Feedback Service v2.0 ===");
    printf("What's your name? ");
    if (!fgets(name, sizeof(name), stdin)) return 0;
    name[strcspn(name, "\n")] = 0;

    printf("Hello, %s! Please leave some feedback about today's service:\n", name);
    if (!fgets(feedback, sizeof(feedback), stdin)) return 0;
    feedback[strcspn(feedback, "\n")] = 0;

    /* VULNERABLE: the attacker-controlled feedback string is passed
     * directly to printf() as the FORMAT STRING, instead of as data:
     *     printf("%s", feedback);   <- this would be safe
     *     printf(feedback);         <- this is what we actually do
     * Any %x, %p, %s, or %n the attacker includes gets interpreted. */
    printf(feedback);
    printf("\n");

    if (unlocked) {
        puts("Thank you! As a reward for your detailed feedback:");
        print_flag();
    } else {
        puts("Thanks for your feedback!");
    }
    return 0;
}
