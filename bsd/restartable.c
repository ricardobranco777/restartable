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
#include <sys/sysctl.h>
#include <util.h>
#elif defined(__DragonFly__)
#include <sys/kinfo.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <vis.h>

#if defined(__NetBSD__)
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
	(void) strvis(vis, arg, VIS_TAB | VIS_NL | VIS_CSTYLE);

	return vis;
}

static void
print_argv(pid_t pid) {
	char **argv = kinfo_getargv(pid);
	char **argvp = argv;

	if (argv == NULL) {
		warn("%d: kinfo_getargv", pid);
		return;
	}
	printf("\t");
	do {
		printf(" %s", safe_arg(*argv));
	} while (*++argv);
	printf("\n");

	free_argv(argvp);
}

static void
print_proc(const struct kinfo_proc *kp) {
#if defined(__FreeBSD__) || defined(__DragonFly__)
	int i, count;
#elif defined(__NetBSD__)
	unsigned int i;
	size_t count;
#endif

	if (kp->ki_pid == 0)
		return;

	struct kinfo_vmentry *vmmap = kinfo_getvmmap(kp->ki_pid, &count);
	if (vmmap == NULL) {
		if (errno != EPERM && errno != ENOENT)
			warn("kinfo_getvmmap(): %d", kp->ki_pid);
		return;
	}

	for (i = 0; i < count; i++)
		if (vmmap[i].kve_type == KVME_TYPE_VNODE && vmmap[i].kve_protection & KVME_PROT_EXEC && vmmap[i].kve_path[0] == '\0') {
			printf("%d\t%d\t%d\t%s\t%s\n", kp->ki_pid, kp->ki_ppid, kp->ki_ruid, kp->ki_login, safe_arg(kp->ki_comm));
			if (verbose)
				print_argv(kp->ki_pid);
			break;
		}

	free(vmmap);
}

static int
print_all(void) {
	struct kinfo_proc *procs;
	int count;

	procs = kinfo_getallproc(&count);
	if (procs == NULL)
		err(1, "kinfo_getallproc()");

	for (int i = 0; i < count; i++)
		print_proc(&procs[i]);

	free(procs);
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
