// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if GOOS_openbsd
#include <sys/sysctl.h>
#endif

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
#if GOOS_openbsd
	// W^X not allowed by default on OpenBSD.
	int prot = PROT_READ | PROT_WRITE;
#elif GOOS_netbsd
	// W^X not allowed by default on NetBSD (PaX MPROTECT).
	int prot = PROT_READ | PROT_WRITE | PROT_MPROTECT(PROT_EXEC);
#else
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
#endif

	int flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED;
#if GOOS_freebsd
	// Fail closed if the chosen data offset conflicts with an existing mapping.
	flags |= MAP_EXCL;
#endif

	if (mmap(data, data_size, prot, flags, -1, 0) != data)
		fail("mmap of data segment failed");

	// Makes sure the file descriptor limit is sufficient to map control pipes.
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kMaxFd;
	setrlimit(RLIMIT_NOFILE, &rlim);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	return __syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}

#if GOOS_freebsd || GOOS_openbsd || GOOS_netbsd

static void cover_open(cover_t* cov, bool extra)
{
	size_t mmap_alloc_size = kCoverSize * 8;
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
	*(uint64*)cov->data = 0;
}

static void cover_collect(cover_t* cov)
{
	cov->size = *(uint64*)cov->data;
}

static bool cover_check(uint32 pc)
{
	return true;
}

static bool cover_check(uint64 pc)
{
	return true;
}
#else
#include "nocover.h"
#endif

#if GOOS_netbsd
#define SYZ_HAVE_FEATURES 1
static feature_t features[] = {
    {"usb", setup_usb},
    {"fault", setup_fault},
};

static void setup_sysctl(void)
{
}
#endif
