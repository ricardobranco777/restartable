/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Ricardo Branco
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#if defined(__FreeBSD__)
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <libprocstat.h>
#elif defined(__NetBSD__)
#include <sys/sysctl.h>
#include <util.h>
#include <kvm.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <vis.h>


#ifdef __FreeBSD__
#define kvm_t	struct procstat
#endif

#ifdef __NetBSD__
#define kinfo_proc	kinfo_proc2
#define kvm_getargv	kvm_getargv2
#define ki_comm	 	p_comm
#define ki_login	p_login
#define ki_pid	 	p_pid
#define ki_ppid	 	p_ppid
#define ki_ruid	 	p_ruid
#endif

static int verbose = 0;

/* Avoid ANSI terminal injection from processes that overwrite their argv */
static char *
safe_arg(char *arg) {
	static char *vis = NULL;

	if (vis == NULL)
		vis = malloc(PATH_MAX * 4 + 1);
	if (vis == NULL)
		err(1, "malloc");
	(void) strnvis(vis, PATH_MAX * 4 + 1, arg, VIS_TAB | VIS_NL | VIS_CSTYLE);

	return vis;
}

static void
print_argv(kvm_t *kd, struct kinfo_proc *kp) {
#if defined(__FreeBSD__)
	char **argv = procstat_getargv(kd, kp, 0);
#elif defined(__NetBSD__)
	char **argv = kvm_getargv(kd, kp, 0);
#endif

	if (argv == NULL) {
#if defined(__FreeBSD__)
		warn("procstat_getargv(): %d", kp->ki_pid);
#elif defined(__NetBSD__)
		warnx("kvm_getargv(): %d: %s", kp->ki_pid, kvm_geterr(kd));
#endif
		return;
	}
	printf("\t");
	do {
		printf(" %s", safe_arg(*argv));
	} while (*++argv);
	printf("\n");

#ifdef __FreeBSD__
	procstat_freeargv(kd);
#endif
}

static void
print_proc(kvm_t *kd, struct kinfo_proc *kp) {
#if defined(__FreeBSD__)
	int i, count;
#elif defined(__NetBSD__)
	unsigned int i;
	size_t count;
#endif

	if (kp->ki_pid == 0)
		return;

#if defined(__FreeBSD__)
	struct kinfo_vmentry *vmmap = procstat_getvmmap(kd, kp, &count);
#elif defined(__NetBSD__)
	struct kinfo_vmentry *vmmap = kinfo_getvmmap(kp->ki_pid, &count);
	if (vmmap == NULL)
		err(1, "kinfo_getvmmap(): %d", kp->ki_pid);
#endif

	for (i = 0; i < count; i++)
		if (vmmap[i].kve_type == KVME_TYPE_VNODE && vmmap[i].kve_protection & KVME_PROT_EXEC && vmmap[i].kve_path[0] == '\0') {
			printf("%d\t%d\t%d\t%s\t%s\n", kp->ki_pid, kp->ki_ppid, kp->ki_ruid, kp->ki_login, kp->ki_comm);
			if (verbose)
				print_argv(kd, kp);
			break;
		}

#if defined(__FreeBSD__)
	procstat_freevmmap(kd, vmmap);
#elif defined(__NetBSD__)
	free(vmmap);
#endif
}

#ifdef __NetBSD__
/*
 * Sort processes by pid
 */
static int
kinfo_proc_compare(const void *a, const void *b)
{
	return ((const struct kinfo_proc2 *)a)->p_pid - ((const struct kinfo_proc2 *)b)->p_pid;
}

static void
kinfo_proc_sort(struct kinfo_proc2 *kipp, int count)
{

	qsort(kipp, count, sizeof(*kipp), kinfo_proc_compare);
}
#endif

static int
print_all(void) {
#ifdef __NetBSD__
	char errbuf[_POSIX2_LINE_MAX];
#endif
	struct kinfo_proc *procs;
	int count;
	kvm_t *kd;

#if defined(__FreeBSD__)
	/* Doesn't work if security.bsd.unprivileged_proc_debug=0 */
	kd = procstat_open_sysctl();
	if (kd == NULL)
		err(1, "procstat_open_sysctl()");
	procs = procstat_getprocs(kd, KERN_PROC_PROC, 0, &count);
	if (procs == NULL)
		err(1, "procstat_getprocs()");
#elif defined(__NetBSD__)
	kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);
	if (kd == NULL)
		errx(1, "kvm_openfiles(): %s", errbuf);

	procs = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &count);
	kinfo_proc_sort(procs, count / sizeof(*procs));
	if (procs == NULL)
		 err(1, "kvm_getproc2(): %s", kvm_geterr(kd));
#endif

	for (int i = 0; i < count; i++)
		print_proc(kd, &procs[i]);

#if defined(__FreeBSD__)
	procstat_freeprocs(kd, procs);
	procstat_close(kd);
#elif defined(__NetBSD__)
	free(procs);
	(void)kvm_close(kd);
#endif
	return 0;
}

int
main(int argc, char *argv[]) {
	if (argc > 2)
		errx(1, "Usage: %s [-v]\n", argv[0]);
	if (argc > 1 && !strcmp(argv[1], "-v"))
		verbose = 1;

	printf("PID\tPPID\tUID\tUser\tCommand\n");
	exit(print_all() != 0);
}
