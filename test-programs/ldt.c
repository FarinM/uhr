/*
 * Test program that runs 32-bit x86 code from a code segment in its LDT,
 * as Wine can: it spins there for about 300 ms on a 3.5 GHz core. It
 * makes system calls itself, so it builds without 32-bit libraries or
 * headers.
 *
 * Build: cc -m32 -static -nostdlib -O2 -o ldt ldt.c
 * Usage: ldt
 */
#define SYS_EXIT 1
#define SYS_MODIFY_LDT 123

/* The kernel's struct user_desc. */
struct user_desc {
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit : 1;
	unsigned int contents : 2;
	unsigned int read_exec_only : 1;
	unsigned int limit_in_pages : 1;
	unsigned int seg_not_present : 1;
	unsigned int useable : 1;
};

static volatile unsigned int sink;

static long syscall3(long number, long a, long b, long c)
{
	long result;
	__asm__ volatile("int $0x80"
			 : "=a"(result)
			 : "a"(number), "b"(a), "c"(b), "d"(c)
			 : "memory");
	return result;
}

__attribute__((noinline)) static void spin(void)
{
	unsigned int x = 2463534242u;

	for (unsigned int i = 0; i < 300000000; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
	}
	sink = x;
}

__attribute__((noreturn)) void run(void)
{
	/* Flat, as the kernel's own 32-bit code segment is. */
	struct user_desc code = {
		.entry_number = 0,
		.limit = 0xfffff,
		.seg_32bit = 1,
		.contents = 2,
		.limit_in_pages = 1,
	};

	if (syscall3(SYS_MODIFY_LDT, 0x11, (long)&code, sizeof(code)) != 0)
		syscall3(SYS_EXIT, 1, 0, 0);
	/* The LDT's first entry, at user privilege. */
	__asm__ volatile("ljmp $0x7, $1f\n1:" ::: "memory");
	spin();
	syscall3(SYS_EXIT, 0, 0, 0);
	__builtin_unreachable();
}

__asm__(".globl _start\n"
	"_start:\n"
	"\tcall run\n");
