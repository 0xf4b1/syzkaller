// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static bool detect_kernel_bitness();

static void os_init(int argc, char** argv, char* data, size_t data_size)
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	is_kernel_64_bit = detect_kernel_bitness();
	// Surround the main data mapping with PROT_NONE pages to make virtual address layout more consistent
	// across different configurations (static/non-static build) and C repros.
	// One observed case before: executor had a mapping above the data mapping (output region),
	// while C repros did not have that mapping above, as the result in one case VMA had next link,
	// while in the other it didn't and it caused a bug to not reproduce with the C repro.
	if (mmap(data - SYZ_PAGE_SIZE, SYZ_PAGE_SIZE, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data - SYZ_PAGE_SIZE)
		fail("mmap of left data PROT_NONE page failed");
	if (mmap(data, data_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data)
		fail("mmap of data segment failed");
	if (mmap(data + data_size, SYZ_PAGE_SIZE, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data + data_size)
		fail("mmap of right data PROT_NONE page failed");
}

static __thread cover_t* current_cover;

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	intptr_t res = syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5]);
	// Some prctl commands don't respect the normal convention for return values
	// (e.g. PR_GET_TIMERSLACK, but there are more) and may produce all possible
	// errno values. This conflicts with fallback coverage.
	if (!flag_coverage && res == -1 && !strcmp(c->name, "prctl"))
		errno = EINVAL;
	return res;
}

static void cover_open(cover_t* cov, bool extra)
{
	size_t mmap_alloc_size = kCoverSize * (is_kernel_64_bit ? 8 : 4);
	cov->data = (char*)mmap((void*)0x10000, mmap_alloc_size,
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memset(cov->data, 0x0, mmap_alloc_size);

	// hypercall to signal coverage buffer for current thread
	asm("int $3" ::"a"(0x41), "b"(cov->data));

	if (cov->data == MAP_FAILED)
		fail("cover mmap failed");
	cov->data_end = cov->data + mmap_alloc_size;
}

static void cover_protect(cover_t* cov)
{
}

static void cover_unprotect(cover_t* cov)
{
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
}

static void cover_reset(cover_t* cov)
{
	// Callers in common_linux.h don't check this flag.
	if (!flag_coverage)
		return;
	if (cov == 0) {
		if (current_cover == 0)
			fail("cover_reset: current_cover == 0");
		cov = current_cover;
	}
	*(uint64*)cov->data = 0;
}

static void cover_collect(cover_t* cov)
{
	if (is_kernel_64_bit)
		cov->size = *(uint64*)cov->data;
	else
		cov->size = *(uint32*)cov->data;
}

static bool cover_check(uint32 pc)
{
	return true;
}

static bool cover_check(uint64 pc)
{
#if defined(__i386__) || defined(__x86_64__)
	// Text/modules range for x86_64.
	return pc >= 0xffffffff80000000ull && pc < 0xffffffffff000000ull;
#else
	return true;
#endif
}

static bool detect_kernel_bitness()
{
	if (sizeof(void*) == 8)
		return true;
	// It turns out to be surprisingly hard to understand if the kernel underneath is 64-bits.
	// A common method is to look at uname.machine. But it is produced in some involved ways,
	// and we will need to know about all strings it returns and in the end it can be overriden
	// during build and lie (and there are known precedents of this).
	// So instead we look at size of addresses in /proc/kallsyms.
	bool wide = true;
	int fd = open("/proc/kallsyms", O_RDONLY);
	if (fd != -1) {
		char buf[16];
		if (read(fd, buf, sizeof(buf)) == sizeof(buf) &&
		    (buf[8] == ' ' || buf[8] == '\t'))
			wide = false;
		close(fd);
	}
	debug("detected %d-bit kernel\n", wide ? 64 : 32);
	return wide;
}

// One does not simply exit.
// _exit can in fact fail.
// syzkaller did manage to generate a seccomp filter that prohibits exit_group syscall.
// Previously, we get into infinite recursion via segv_handler in such case
// and corrupted output_data, which does matter in our case since it is shared
// with fuzzer process. Loop infinitely instead. Parent will kill us.
// But one does not simply loop either. Compilers are sure that _exit never returns,
// so they remove all code after _exit as dead. Call _exit via volatile indirection.
// And this does not work as well. _exit has own handling of failing exit_group
// in the form of HLT instruction, it will divert control flow from our loop.
// So call the syscall directly.
NORETURN void doexit(int status)
{
	volatile unsigned i;
	syscall(__NR_exit_group, status);
	for (i = 0;; i++) {
	}
}

#define SYZ_HAVE_FEATURES 1
static feature_t features[] = {
    {"leak", setup_leak},
    {"fault", setup_fault},
    {"binfmt_misc", setup_binfmt_misc},
    {"kcsan", setup_kcsan},
    {"usb", setup_usb},
};
