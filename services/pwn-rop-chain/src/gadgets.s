/* Two deliberately provided ROP gadgets for pwn-rop-chain. Reaching
 * win() with the right arguments requires chaining BOTH of these
 * together: pop_rdi_ret sets the first argument (rdi), then
 * pop_rsi_rdx_ret sets the second and third (rsi, rdx) in one go.
 */
.global pop_rdi_ret
pop_rdi_ret:
    pop %rdi
    ret

.global pop_rsi_rdx_ret
pop_rsi_rdx_ret:
    pop %rsi
    pop %rdx
    ret
