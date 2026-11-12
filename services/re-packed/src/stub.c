/* re-packed: a tiny self-extracting "packer" stub, in the same spirit
 * as UPX (a real, extremely common executable packer). No external
 * packer tool is used here -- this stub is a small, dependency-free
 * stand-in built with ordinary zlib compression, so the challenge
 * stays buildable/testable with nothing beyond what's already on this
 * platform. The LESSON is identical either way: the file you can
 * connect to and run is not the actual program's code -- it's a
 * compressed copy of it wrapped in a tiny loader that decompresses
 * the real program into a temp file and runs THAT instead.
 *
 * `strings`/`objdump` run directly against THIS binary show you
 * nothing useful about the real program's logic (just compressed,
 * high-entropy bytes) -- that's the entire point of packing.
 * Decompress first, then analyze the real binary exactly like any
 * unpacked one (see re-crackme).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <zlib.h>

#include "packed_payload.h"  /* defines PACKED_DATA[], PACKED_LEN, UNPACKED_LEN */

int main(void) {
    unsigned char *out = malloc(UNPACKED_LEN);
    if (!out) {
        return 1;
    }
    uLongf out_len = UNPACKED_LEN;
    int rc = uncompress(out, &out_len, PACKED_DATA, PACKED_LEN);
    if (rc != Z_OK || out_len != UNPACKED_LEN) {
        fprintf(stderr, "unpack failed (rc=%d)\n", rc);
        free(out);
        return 1;
    }

    char tmpl[] = "/tmp/.unpacked_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        free(out);
        return 1;
    }
    write(fd, out, out_len);
    close(fd);
    chmod(tmpl, 0755);
    free(out);

    /* Replace this process with the unpacked program, passing stdio
     * straight through -- same visible behavior as running the inner
     * binary directly, once you've unpacked it yourself. */
    execl(tmpl, tmpl, (char *)NULL);

    /* execl only returns on failure */
    unlink(tmpl);
    return 1;
}
