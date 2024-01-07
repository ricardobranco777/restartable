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
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/user.h>
#include <libutil.h>

void
print_proc(const struct kinfo_proc *kp) {
	struct kinfo_vmentry *vmmap;
	int i, count;

	vmmap = kinfo_getvmmap(kp->ki_pid, &count);
	if (vmmap == NULL && errno != EPERM)
		err(1, "kinfo_getvmmap(): %d", kp->ki_pid);

	for (i = 0; i < count; i++)
		if (vmmap[i].kve_type == KVME_TYPE_VNODE && vmmap[i].kve_protection & VM_PROT_EXECUTE && vmmap[i].kve_path[0] == '\0')
			printf("%d\t%d\t%d\t%s\t%s\n", kp->ki_pid, kp->ki_ppid, kp->ki_ruid, kp->ki_login, kp->ki_comm);

	free(vmmap);
}

int
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
main(void) {
	printf("PID\tPPID\tUID\tUser\tCommand\n");
	exit(print_all() != 0);
}
