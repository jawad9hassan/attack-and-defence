/* A single, deliberately provided ROP gadget for pwn-ret2libc:
 * "pop rdi; ret" -- used to load the one argument needed for both
 * stages of the exploit (puts()'s GOT address for the leak, then
 * "/bin/sh"'s libc address for the final system() call) into the
 * first integer argument register per the x86-64 calling convention.
 */
.global pop_rdi_ret
pop_rdi_ret:
    pop %rdi
    ret
