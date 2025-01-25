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
#endif
#include <sys/sysctl.h>
#include <kvm.h>

#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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

#ifdef __NetBSD__
#define kinfo_proc	kinfo_proc2
#define kvm_getargv	kvm_getargv2
#endif

#ifndef KVM_NO_FILES
#define KVM_NO_FILES	0
#endif

#include "extern.h"

#define VERSION	"2.3.4"

static int verbose = 0;

/*
 * Sort processes by pid
 */
#ifdef __OpenBSD__
typedef struct kinfo_file kinfo_t;
#else
typedef struct kinfo_proc kinfo_t;
#endif

static int
kinfo_proc_compare(const void *a, const void *b)
{
	return ((const kinfo_t *)a)->ki_pid -
		((const kinfo_t *)b)->ki_pid;
}

static void
kinfo_proc_sort(kinfo_t *k, int count)
{
	qsort(k, count, sizeof(*k), kinfo_proc_compare);
}

#ifndef __OpenBSD__
static char *
kinfo_getpathname(pid_t pid)
{
	static char path[MAXPATHLEN];
#if defined(__FreeBSD__) || defined(__DragonFly__)
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid};
#elif defined(__NetBSD__)
	int mib[4] = {CTL_KERN, KERN_PROC_ARGS, pid, KERN_PROC_PATHNAME};
#endif
	size_t len = MAXPATHLEN;

	if (sysctl(mib, 4, path, &len, NULL, 0) < 0)
		return (NULL);
	path[len] = '\0';

	return (path);
}
#endif

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
print_argv(kvm_t *kd, struct kinfo_proc *kp) {
	char **argv = kvm_getargv(kd, kp, 0);
	if (argv == NULL) {
		warn("kvm_getargv(): %d: %s", kp->ki_pid, kvm_geterr(kd));
		return;
	}
	printf("\t");
#ifndef __OpenBSD__
	if (*argv[0] != '/') {
		char *arg0 = kinfo_getpathname(kp->ki_pid);
		if (arg0 != NULL)
			*argv = arg0;
	}
#endif
	do {
		printf(" %s", safe_arg(*argv));
	} while (*++argv);
	printf("\n");
}

static void
print_proc(kvm_t *kd, struct kinfo_proc *kp) {
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
				print_argv(kd, kp);
			break;
		}

	free(vmmap);

#else	/* __OpenBSD__ */
	printf("%d\t%d\t%d\t%s\t%s\n", kp->ki_pid, kp->ki_ppid,
	    kp->ki_ruid, kp->ki_login, safe_arg(kp->ki_comm));
	if (verbose)
		print_argv(kd, kp);
#endif
}

static int
print_all(void) {
	char errstr[_POSIX2_LINE_MAX];
#ifdef __OpenBSD__
	struct kinfo_file *files;
#else
	struct kinfo_proc *procs;
#endif
	kvm_t *kd;
	int count;

	kd = kvm_openfiles(_PATH_DEVNULL, _PATH_DEVNULL, _PATH_DEVNULL, O_RDONLY | KVM_NO_FILES, errstr);
	if (kd == NULL)
		errx(1, "kvm_openfiles(): %s", errstr);

#ifdef __OpenBSD__
	files = kvm_getfiles(kd, KERN_FILE_BYPID, -1, sizeof(*files), &count);
	if (files == NULL)
		errx(1, "kvm_getfiles(): %s", kvm_geterr(kd));
	kinfo_proc_sort(files, count);

	if (pledge("stdio rpath getpw ps", NULL) == -1)
		err(1, "pledge");

	for (int i = 0; i < count; i++) {
		struct kinfo_file *kf = &files[i];
		struct kinfo_proc *kp;
		int rc;

		if (kf->v_flag != VTEXT || kf->va_nlink != 0)
			continue;

		kp = kvm_getprocs(kd, KERN_PROC_PID, kf->ki_pid, sizeof(struct kinfo_proc), &rc);
		if (kp == NULL) {
			warn("kvm_getprocs(): %d: %s", kf->ki_pid, kvm_geterr(kd));
			continue;
		}

		print_proc(kd, kp);
	}
#else

#if defined(__NetBSD__)
	procs = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &count);
#elif defined(__FreeBSD__)
	procs = kvm_getprocs(kd, KERN_PROC_PROC, 0, &count);
#elif defined(__DragonFly__)
	procs = kvm_getprocs(kd, KERN_PROC_ALL, 0, &count);
#endif
	if (procs == NULL)
		errx(1, "kvm_getprocs(): %s", kvm_geterr(kd));
	kinfo_proc_sort(procs, count);

	for (int i = 0; i < count; i++)
		print_proc(kd, &procs[i]);
#endif	/* !__OpenBSD__ */

	(void)kvm_close(kd);
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
usage(void) {
	fprintf(stderr, "Usage: %s [-v|--verbose]\n", getprogname());
	exit(1);
}

static void
version(void) {
	printf("%s %s\n", getprogname(), VERSION);
}

int
main(int argc, char *argv[]) {
	int ch;
	struct option longopts[] = {
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
	};

	while ((ch = getopt_long(argc, argv, "v", longopts, NULL)) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		case 'V':
			version();
			return (0);
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

#ifndef __OpenBSD__
	if (geteuid())
#endif
		check_sysctl();

	printf("PID\tPPID\tUID\tUser\tCommand\n");
	exit(print_all() != 0);
}
