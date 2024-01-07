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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/user.h>
#include <libutil.h>

#include <fcntl.h>
#include <kvm.h>
#include <limits.h>	/* _POSIX2_LINE_MAX */
#include <paths.h>	/* _PATH_DEVNULL */

static int verbose = 0;

static void
print_argv(kvm_t *kd, const struct kinfo_proc *kp) {
	char **argv = kvm_getargv(kd, kp, 0);

	if (argv == NULL) {
		warn("kvm_getargv(): %d: %s", kp->ki_pid, kvm_geterr(kd));
		return;
	}
	printf("\t");
	do {
		printf(" %s", *argv);
	} while (*++argv);
	printf("\n");
}

static void
print_proc(kvm_t *kd, const struct kinfo_proc *kp) {
	struct kinfo_vmentry *vmmap;
	int i, count;

	vmmap = kinfo_getvmmap(kp->ki_pid, &count);
	if (vmmap == NULL && errno != EPERM)
		err(1, "kinfo_getvmmap(): %d", kp->ki_pid);

	for (i = 0; i < count; i++)
		if (vmmap[i].kve_type == KVME_TYPE_VNODE && vmmap[i].kve_protection & VM_PROT_EXECUTE && vmmap[i].kve_path[0] == '\0') {
			printf("%d\t%d\t%d\t%s\t%s\n", kp->ki_pid, kp->ki_ppid, kp->ki_ruid, kp->ki_login, kp->ki_comm);
			if (verbose)
				print_argv(kd, kp);
			break;
		}

	free(vmmap);
}

static int
print_all(void) {
	char errbuf[_POSIX2_LINE_MAX];
	struct kinfo_proc *procs;
	kvm_t *kd;
	int count;

	kd = kvm_openfiles(_PATH_DEVNULL, _PATH_DEVNULL, NULL, O_RDONLY, errbuf);
	if (kd == NULL)
		errx(1, "kvm_openfiles(): %s", errbuf);

	procs = kinfo_getallproc(&count);
	if (procs == NULL)
		err(1, "kinfo_getallproc()");

	for (int i = 0; i < count; i++)
		print_proc(kd, &procs[i]);

	free(procs);
	(void)kvm_close(kd);
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
