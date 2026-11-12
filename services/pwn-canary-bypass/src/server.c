/* pwn-canary-bypass: a small forking TCP server with a classic stack
 * buffer overflow -- but THIS time, the binary is compiled WITH a
 * stack canary (GCC's default stack protector), so a naive overflow
 * that reaches the saved return address crashes the process (the
 * canary check fails and the program aborts) before it can ever jump
 * anywhere.
 *
 * The server forks a new child to handle each connection, but NEVER
 * calls exec() again -- the child is a straight fork() of the already-
 * running parent process. That matters: the stack canary's value
 * (__stack_chk_guard) is set ONCE, when the process starts, from
 * /dev/urandom. fork() duplicates the parent's memory, canary value
 * included, so EVERY child spawned by this server shares the exact
 * same canary value for as long as the parent process keeps running.
 * This is exactly the situation that makes a byte-by-byte canary
 * brute force practical against a real network service: guess one
 * byte at a time, reconnecting (which gets you a fresh child, but
 * with the SAME canary) whenever a guess is wrong and the connection
 * dies.
 *
 * Within ONE connection, you can send as many guesses as you want --
 * the vulnerable function is called in a loop, once per line of
 * input, and a wrong canary byte only kills that one call (the
 * process aborts, the connection drops, but the attacker just opens a
 * new connection to a fresh child carrying the same canary).
 *
 * Protocol (plain text over TCP): each line is one guess, exactly
 * up to PAYLOAD_LEN bytes, hex-encoded (two hex characters per byte).
 * The server replies "OK" if the call returned normally, or the
 * connection simply dies (stack smashing detected) if the canary
 * check failed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUF_SIZE 64
#define PAYLOAD_LEN 256
#define PORT 9992

void win(void) {
    char flag[256];
    FILE *f = fopen("/flag.txt", "r");
    if (!f) { dprintf(1, "[server error] flag file missing\n"); _exit(1); }
    if (fgets(flag, sizeof(flag), f)) { dprintf(1, "WIN: %s", flag); }
    fclose(f);
    _exit(0);
}

__attribute__((noinline))
void vulnerable_once(const unsigned char *data, size_t len) {
    char buf[BUF_SIZE];
    if (len > PAYLOAD_LEN) len = PAYLOAD_LEN;
    memcpy(buf, data, len);
}

static ssize_t read_line(int fd, char *out, size_t max) {
    size_t n = 0;
    while (n + 1 < max) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return (n == 0) ? -1 : (ssize_t)n;
        if (c == '\n') break;
        out[n++] = c;
    }
    out[n] = '\0';
    return (ssize_t)n;
}

static void handle_client(int fd) {
    char line[PAYLOAD_LEN * 2 + 8];
    unsigned char payload[PAYLOAD_LEN];
    char hexbuf[3];

    dprintf(fd, "Send hex payload (one guess per line, up to %d bytes).\n", PAYLOAD_LEN);

    for (;;) {
        ssize_t n = read_line(fd, line, sizeof(line));
        if (n < 0) break;
        if (n == 0) continue;
        if (n % 2 != 0) { dprintf(fd, "ERROR: odd-length hex\n"); continue; }
        size_t plen = n / 2;
        if (plen > PAYLOAD_LEN) { dprintf(fd, "ERROR: too long\n"); continue; }
        int bad = 0;
        for (size_t i = 0; i < plen; i++) {
            hexbuf[0] = line[i * 2]; hexbuf[1] = line[i * 2 + 1]; hexbuf[2] = '\0';
            char *endp;
            long v = strtol(hexbuf, &endp, 16);
            if (*endp != '\0') { bad = 1; break; }
            payload[i] = (unsigned char)v;
        }
        if (bad) { dprintf(fd, "ERROR: not valid hex\n"); continue; }

        vulnerable_once(payload, plen);
        dprintf(fd, "OK\n");
    }
}

int main(void) {
    signal(SIGCHLD, SIG_IGN);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, 16) < 0) { perror("listen"); return 1; }

    dprintf(1, "canary-bypass server listening on 0.0.0.0:%d\n", PORT);
    fflush(NULL);

    for (;;) {
        int conn_fd = accept(listen_fd, NULL, NULL);
        if (conn_fd < 0) continue;

        pid_t pid = fork();
        if (pid == 0) {
            close(listen_fd);
            dup2(conn_fd, 1);
            handle_client(conn_fd);
            close(conn_fd);
            _exit(0);
        }
        close(conn_fd);
    }
}
