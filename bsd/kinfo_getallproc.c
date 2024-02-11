#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <stdlib.h>

#include "extern.h"

/*
 * Sort processes by pid
 */
static int
kinfo_proc_compare(const void *a, const void *b)
{

	return ((const struct kinfo_proc *)a)->p_pid -
	    ((const struct kinfo_proc *)b)->p_pid;
}

static void
kinfo_proc_sort(struct kinfo_proc *kipp, int count)
{

	qsort(kipp, count, sizeof(*kipp), kinfo_proc_compare);
}

struct kinfo_proc *
kinfo_getallproc(int *cntp)
{
	struct kinfo_proc *kipp;
	size_t len;
	int mib[6];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC2;
	mib[2] = KERN_PROC_ALL;
	mib[3] = 0;
	mib[4] = sizeof(struct kinfo_proc);
	mib[5] = 0;

	len = 0;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		return (NULL);
	mib[5] = (int) (len / sizeof(struct kinfo_proc));

	kipp = malloc(len);
	if (kipp == NULL)
		return (NULL);

	if (sysctl(mib, 6, kipp, &len, NULL, 0) < 0)
		goto bad;
	*cntp = len / sizeof(*kipp);
	kinfo_proc_sort(kipp, len / sizeof(*kipp));
	return (kipp);

bad:
	*cntp = 0;
	free(kipp);
	return (NULL);
}
