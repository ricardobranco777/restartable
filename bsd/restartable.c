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
#if defined(__FreeBSD__)
#include <sys/user.h>
#include <libutil.h>
#elif defined(__NetBSD__)
#include <sys/param.h>
#include <util.h>
#elif defined(__DragonFly__)
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/kinfo.h>
#elif defined(__OpenBSD__)
#include <sys/param.h>
#include <sys/vnode.h>
#include <kvm.h>
#endif
#include <sys/sysctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <vis.h>

#if defined(__NetBSD__) || defined(__OpenBSD__)
#define ki_comm		p_comm
#define ki_login	p_login
#define ki_pid		p_pid
#define ki_ppid		p_ppid
#define ki_ruid		p_ruid
#elif defined(__DragonFly__)
#define ki_comm		kp_comm
#define ki_login	kp_login
#define ki_pid		kp_pid
#define ki_ppid		kp_ppid
#define ki_ruid		kp_ruid
#endif

#include "extern.h"

static int verbose = 0;

/* Avoid ANSI terminal injection from processes that overwrite their argv */
static char *
safe_arg(const char *arg) {
	static char *vis = NULL;

	if (vis == NULL)
		vis = malloc(PATH_MAX * 4 + 1);
	if (vis == NULL)
		err(1, "malloc");
	(void)strvis(vis, arg, VIS_TAB | VIS_NL | VIS_CSTYLE);

	return (vis);
}

static void
#ifdef __OpenBSD__
print_argv(kvm_t *kd, struct kinfo_proc *kp) {
	char **argv = kvm_getargv(kd, kp, 0);
#else
print_argv(pid_t pid) {
	char **argv = kinfo_getargv(pid);
	char **argvp = argv;
#endif

	if (argv == NULL) {
#ifdef __OpenBSD__
		warn("kvm_getargv(): %d: %s", kp->p_pid, kvm_geterr(kd));
#else
		warn("kinfo_getargv(): %d", pid);
#endif
		return;
	}
	printf("\t");
	do {
		printf(" %s", safe_arg(*argv));
	} while (*++argv);
	printf("\n");

#ifndef __OpenBSD__
	free_argv(argvp);
#endif
}

#ifdef __OpenBSD__
static int
kinfo_file_compare(const void *a, const void *b)
{

	return ((const struct kinfo_file *)a)->p_pid -
	    ((const struct kinfo_file *)b)->p_pid;
}

static void
kinfo_file_sort(struct kinfo_file *kifp, int count)
{

	qsort(kifp, count, sizeof(*kifp), kinfo_file_compare);
}
#endif

static void
#ifdef __OpenBSD__
print_proc(kvm_t *kd, struct kinfo_proc *kp) {
#else
print_proc(const struct kinfo_proc *kp) {
#endif
#if defined(__FreeBSD__) || defined(__DragonFly__)
	int i, count;
#elif defined(__NetBSD__)
	unsigned int i;
	size_t count;
#endif

#ifndef __OpenBSD__
	if (kp->ki_pid == 0)
		return;

	struct kinfo_vmentry *vmmap = kinfo_getvmmap(kp->ki_pid, &count);
	if (vmmap == NULL) {
		if (errno != EPERM && errno != ENOENT)
			warn("kinfo_getvmmap(): %d", kp->ki_pid);
		return;
	}

	for (i = 0; i < count; i++)
		if (vmmap[i].kve_type == KVME_TYPE_VNODE &&
		    vmmap[i].kve_protection & KVME_PROT_EXEC &&
		    vmmap[i].kve_path[0] == '\0') {
			printf("%d\t%d\t%d\t%s\t%s\n", kp->ki_pid, kp->ki_ppid,
			    kp->ki_ruid, kp->ki_login, safe_arg(kp->ki_comm));
			if (verbose)
				print_argv(kp->ki_pid);
			break;
		}

	free(vmmap);

#else	/* !__OpenBSD__ */
	printf("%d\t%d\t%d\t%s\t%s\n", kp->ki_pid, kp->ki_ppid,
	    kp->ki_ruid, kp->ki_login, safe_arg(kp->ki_comm));
	if (verbose)
		print_argv(kd, kp);
#endif
}

static int
print_all(void) {
#ifdef __OpenBSD__
	char errstr[_POSIX2_LINE_MAX];
	struct kinfo_file *files;
	kvm_t *kd;
	int count;

	kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errstr);
	if (kd == NULL)
		errx(1, "kvm_openfiles(): %s", errstr);

	files = kvm_getfiles(kd, KERN_FILE_BYPID, -1, sizeof(*files), &count);
	if (files == NULL)
		errx(1, "kvm_getfiles(): %s", kvm_geterr(kd));

	kinfo_file_sort(files, count);

	for (int i = 0; i < count; i++) {
		struct kinfo_file *kf = &files[i];
		struct kinfo_proc *kp;
		int rc;

		if (kf->v_flag != VTEXT || kf->va_nlink != 0)
			continue;

		kp = kvm_getprocs(kd, KERN_PROC_PID, kf->p_pid, sizeof(struct kinfo_proc), &rc);
		if (kp == NULL) {
			warn("kvm_getprocs(): %d: %s", kf->p_pid, kvm_geterr(kd));
			continue;
		}

		print_proc(kd, kp);
	}

	(void)kvm_close(kd);
#else	/* !__OpenBSD__ */
	struct kinfo_proc *procs;
	int count;

	procs = kinfo_getallproc(&count);
	if (procs == NULL)
		err(1, "kinfo_getallproc()");

	for (int i = 0; i < count; i++)
		print_proc(&procs[i]);

	free(procs);
#endif	/* !__OpenBSD__ */
	return (0);
}

static void
check_sysctl(void) {
#ifdef __OpenBSD__
	int mib[2] = {CTL_KERN, KERN_ALLOWKMEM};
#endif
#ifdef __DragonFly__
	struct statfs fs;
#endif
	int value;
	size_t len = sizeof(value);
	const char *name= NULL;

#if defined(__FreeBSD__)
	name = "security.bsd.unprivileged_proc_debug";
#elif defined(__NetBSD__)
	name = "security.curtain";
#elif defined(__DragonFly__)
	name = "security.ps_showallprocs";
#elif defined(__OpenBSD__)
	name = "kern.allowkmem";
#endif

#ifdef __OpenBSD__
	if (sysctl(mib, nitems(mib), &value, &len, NULL, 0) == -1)
#else
	if (sysctlbyname(name, &value, &len, NULL, 0) == -1)
#endif
		err(1, "sysctl %s", name);

#ifdef __DragonFly__
	if (statfs("/proc", &fs) < 0 || strcmp(fs.f_mntonname, "/proc"))
		errx(1, "/proc is not mounted");
#endif

#if defined(__NetBSD__)
	if (value)
#else
	if (!value)
#endif
		warnx("%s sysctl is set to %d. Run this program as root", name, value);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [-v]\n", getprogname());
	exit(1);
}

int
main(int argc, char *argv[]) {
	int ch;

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if (argc != 0)
		usage();

	if (geteuid())
		check_sysctl();

	printf("PID\tPPID\tUID\tUser\tCommand\n");
	exit(print_all() != 0);
}
