/*
 * Writes to each page of 64 MiB it maps afresh, which the kernel fills with
 * zeros as each page faults, computes a little, and unmaps them, for 250
 * rounds: of its time in the kernel, about four fifths is in its page
 * faults, under touch(), and the rest in munmap.
 *
 * Build: cc -O2 -o faults faults.c
 * Usage: faults
 */
#include <sys/mman.h>
#include <unistd.h>

#define SIZE (64L << 20)
#define ROUNDS 250

static volatile unsigned long sink;

__attribute__((noinline)) static void touch(char *p, long page)
{
	for (long i = 0; i < SIZE; i += page)
		p[i] = 1;
}

__attribute__((noinline)) static void compute(void)
{
	for (int i = 0; i < 2000000; i++)
		sink += i;
}

int main(void)
{
	long page = sysconf(_SC_PAGESIZE);

	for (int round = 0; round < ROUNDS; round++) {
		char *p = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
		if (p == MAP_FAILED)
			return 1;
		touch(p, page);
		compute();
		munmap(p, SIZE);
	}
	return 0;
}
