#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#ifdef __DragonFly__
#include <sys/user.h>
#else
#include <sys/proc.h>
#endif

#include <stdlib.h>

#include "extern.h"

#ifdef __DragonFly__
#define p_pid	kp_pid
#endif

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
	size_t len = 65;
	int mib[6];
	int n;

	mib[0] = CTL_KERN;
	mib[3] = 0;
#if defined(__NetBSD__)
	mib[1] = KERN_PROC2;
	mib[2] = KERN_PROC_ALL;
	mib[4] = sizeof(struct kinfo_proc);
	mib[5] = 0;
	n = 6;
#elif defined(__DragonFly__)
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_ALL;
	n = 3;
#endif

	len = 0;
	if (sysctl(mib, n, NULL, &len, NULL, 0) < 0)
		return (NULL);
#ifdef __NetBSD__
	mib[n-1] = (int) (len / sizeof(struct kinfo_proc));
#endif

	kipp = malloc(len);
	if (kipp == NULL)
		return (NULL);

	if (sysctl(mib, n, kipp, &len, NULL, 0) < 0)
		goto bad;
	*cntp = len / sizeof(*kipp);
	kinfo_proc_sort(kipp, len / sizeof(*kipp));
	return (kipp);

bad:
	*cntp = 0;
	free(kipp);
	return (NULL);
}
