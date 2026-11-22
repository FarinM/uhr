/*
 * Spends its time in spin(), a function written in assembly that sets up a
 * frame but has no unwind tables, as libm's sin: only the frame record it
 * pushed says who called it. caller() calls it once, and main() caller().
 *
 * Build: cc -O2 -o asm_frame asm_frame.c   (arm64 macOS only)
 * Usage: asm_frame
 */
#include <stdint.h>

#define ROUNDS 2000000000ULL

uint64_t spin(uint64_t rounds);

__asm__(".text\n"
	".globl _spin\n"
	".p2align 2\n"
	"_spin:\n"
	"	stp x29, x30, [sp, #-16]!\n"
	"	mov x29, sp\n"
	"1:	subs x0, x0, #1\n"
	"	b.ne 1b\n"
	"	ldp x29, x30, [sp], #16\n"
	"	ret\n");

/* The add after the call keeps it from becoming a jump, which would leave
 * no frame of caller()'s. */
__attribute__((noinline)) uint64_t caller(uint64_t rounds)
{
	return spin(rounds) + 1;
}

int main(void)
{
	return caller(ROUNDS) != 1;
}
