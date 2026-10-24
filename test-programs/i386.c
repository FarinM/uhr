/*
 * Test program that runs 32-bit x86 code from an executable that is gone:
 * it deletes its own file, then spins for about 300 ms on a 3.5 GHz core.
 * It makes system calls itself, so it builds without 32-bit libraries or
 * headers.
 *
 * Build: cc -m32 -static -nostdlib -O2 -o i386 i386.c
 * Usage: i386
 */
#define SYS_EXIT 1
#define SYS_UNLINK 10

static volatile unsigned int sink;

static long syscall1(long number, long arg)
{
	long result;
	__asm__ volatile("int $0x80" : "=a"(result) : "a"(number), "b"(arg) : "memory");
	return result;
}

/* Called from _start with argv[0]. */
__attribute__((noreturn)) void run(const char *path)
{
	unsigned int x = 2463534242u;

	syscall1(SYS_UNLINK, (long)path);
	for (unsigned int i = 0; i < 300000000; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
	}
	sink = x;
	syscall1(SYS_EXIT, 0);
	__builtin_unreachable();
}

__asm__(".globl _start\n"
	"_start:\n"
	"\tpushl 4(%esp)\n"
	"\tcall run\n");
