/*
 * Maps memory and names it, as allocators and runtimes name theirs, then
 * touches it and keeps it a while.
 *
 * Build: cc -O2 -o named named.c
 * Usage: named [MiB] [ms to keep it]   (32 and 300 by default)
 *
 * Its name ends in a number, as glibc names a thread's stack by its id.
 * Naming memory needs Linux 5.17 or later, built with CONFIG_ANON_VMA_NAME.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#endif

/*
 * Writes a byte to each page, so that every page is resident. Through a
 * volatile pointer, as a compiler may drop writes nothing reads, and in a
 * function of its own, which the page faults are then in.
 */
__attribute__((noinline)) static void touch(volatile char *memory, long bytes)
{
	long page = sysconf(_SC_PAGESIZE);
	for (long at = 0; at < bytes; at += page)
		memory[at] = 1;
}

int main(int argc, char **argv)
{
	long bytes = (argc > 1 ? atol(argv[1]) : 32) << 20;
	long keep_ms = argc > 2 ? atol(argv[2]) : 300;

	char *memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, memory, bytes,
		  "uhr test: 7")) {
		perror("naming memory, which needs Linux 5.17 or later built with CONFIG_ANON_VMA_NAME");
		return 1;
	}
	touch(memory, bytes);
	usleep(keep_ms * 1000);
	return 0;
}
