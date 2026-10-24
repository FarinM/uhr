/*
 * Syscall-heavy test program with known behavior: read_zero() reads
 * /dev/zero in large chunks, so almost all of the CPU time is the kernel
 * clearing the buffer, on behalf of read_zero(). It prints its own user,
 * kernel and elapsed time, measured by the kernel:
 *   process user_ns <n> kernel_ns <n> wall_ns <n>
 *
 * Build: cc -O2 -fno-omit-frame-pointer -Wl,--build-id -o syscalls syscalls.c
 * Usage: syscalls [rounds]   (500000 rounds take under a second on a modern core)
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if defined(__clang__)
#define KEEP __attribute__((noinline))
#else
#define KEEP __attribute__((noipa))
#endif

#define CHUNK (256 * 1024)

static char buffer[CHUNK];

/* libc's read() sets up no frame, so frame-pointer stacks would skip its
 * caller. Entering the kernel from here keeps read_zero() on the stack. */
static inline long sys_read(long fd, void *buf, long count)
{
#if defined(__x86_64__)
	long ret;
	__asm__ volatile("syscall"
			 : "=a"(ret)
			 : "0"((long)SYS_read), "D"(fd), "S"(buf), "d"(count)
			 : "rcx", "r11", "memory");
	return ret;
#elif defined(__aarch64__)
	register long x8 __asm__("x8") = SYS_read;
	register long x0 __asm__("x0") = fd;
	register long x1 __asm__("x1") = (long)buf;
	register long x2 __asm__("x2") = count;
	__asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
	return x0;
#else
#error "no raw syscall for this architecture"
#endif
}

KEEP uint64_t read_zero(int fd, uint64_t rounds)
{
	uint64_t total = 0;
	for (uint64_t r = 0; r < rounds; r++) {
		long n = sys_read(fd, buffer, CHUNK);
		if (n <= 0) {
			fprintf(stderr, "read failed: %ld\n", n);
			exit(1);
		}
		total += (uint64_t)n;
	}
	return total;
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000 + (uint64_t)ts.tv_nsec;
}

static uint64_t ns(struct timeval tv)
{
	return (uint64_t)tv.tv_sec * 1000000000 + (uint64_t)tv.tv_usec * 1000;
}

int main(int argc, char **argv)
{
	uint64_t started = monotonic_ns();
	uint64_t rounds = argc > 1 ? strtoull(argv[1], NULL, 10) : 500000;
	int fd = open("/dev/zero", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/zero");
		return 1;
	}
	printf("%llu\n", (unsigned long long)read_zero(fd, rounds));

	struct rusage usage;
	getrusage(RUSAGE_SELF, &usage);
	printf("process user_ns %llu kernel_ns %llu wall_ns %llu\n",
	       (unsigned long long)ns(usage.ru_utime), (unsigned long long)ns(usage.ru_stime),
	       (unsigned long long)(monotonic_ns() - started));
	return 0;
}
