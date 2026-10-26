/*
 * Runs a virtual machine whose one vCPU spins in place, so nearly all of
 * the thread's time is spent running the guest. Needs /dev/kvm.
 *
 * Build: cc -O2 -o guest guest.c
 * Usage: guest [milliseconds]   (1000 by default)
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

static void alarm_rang(int signal)
{
	(void)signal;
}

static int fail(const char *what)
{
	perror(what);
	return 2;
}

int main(int argc, char **argv)
{
	long ms = argc > 1 ? atol(argv[1]) : 1000;
	int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm < 0)
		return fail("/dev/kvm");
	int vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vm < 0)
		return fail("KVM_CREATE_VM");

	/* One page of real-mode code at 0x1000: jmp $. */
	unsigned char *memory = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
				     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memory[0] = 0xeb;
	memory[1] = 0xfe;
	struct kvm_userspace_memory_region region = {
		.guest_phys_addr = 0x1000,
		.memory_size = 0x1000,
		.userspace_addr = (unsigned long)memory,
	};
	if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) < 0)
		return fail("KVM_SET_USER_MEMORY_REGION");

	int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
	if (vcpu < 0)
		return fail("KVM_CREATE_VCPU");
	struct kvm_sregs sregs;
	if (ioctl(vcpu, KVM_GET_SREGS, &sregs) < 0)
		return fail("KVM_GET_SREGS");
	sregs.cs.base = 0;
	sregs.cs.selector = 0;
	if (ioctl(vcpu, KVM_SET_SREGS, &sregs) < 0)
		return fail("KVM_SET_SREGS");
	struct kvm_regs regs = { .rip = 0x1000, .rflags = 2 };
	if (ioctl(vcpu, KVM_SET_REGS, &regs) < 0)
		return fail("KVM_SET_REGS");

	/* The alarm's signal ends KVM_RUN. */
	struct sigaction action = { .sa_handler = alarm_rang };
	sigaction(SIGALRM, &action, NULL);
	struct itimerval timer = {
		.it_value = { .tv_sec = ms / 1000, .tv_usec = ms % 1000 * 1000 },
	};
	setitimer(ITIMER_REAL, &timer, NULL);
	if (ioctl(vcpu, KVM_RUN, 0) == 0 || errno != EINTR)
		return fail("KVM_RUN");
	return 0;
}
