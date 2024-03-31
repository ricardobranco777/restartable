#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#ifdef __DragonFly__
#include <sys/user.h>
#else
#include <sys/proc.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "extern.h"

static char *kinfo_getpathname(pid_t);

#if !defined(__FreeBSD__)
static char *xbasename(char *s);

static char *
xbasename(char *s) {
	char *t = strrchr(s, '/');
	return (t == NULL ? (char *)s : ++t);
}
#endif

static char *
kinfo_getpathname(pid_t pid)
{
	char path[MAXPATHLEN];
	int mib[4];
	size_t len;

	mib[0] = CTL_KERN;
#if defined(__FreeBSD__) || defined(__DragonFly__)
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = pid;
#elif defined(__NetBSD__)
	mib[1] = KERN_PROC_ARGS;
	mib[2] = pid;
	mib[3] = KERN_PROC_PATHNAME;
#endif
	len = MAXPATHLEN;
	if (sysctl(mib, 4, path, &len, NULL, 0) < 0)
		return (NULL);
	path[len] = '\0';

	return strdup(path);
}

void
free_argv(char **argv)
{
	char **argvp = argv;

	if (argv == NULL)
		return;

	while (*argvp != NULL) {
		free(*argvp);
		argvp++;
	}

	free(argv);
}

char **
kinfo_getargv(pid_t pid)
{
	size_t off = 0, len = ARG_MAX;
	char **argv = NULL;
	char *buf = NULL;
	int i = 0, argc;
	int mib[4];

	buf = malloc(len);
	if (buf == NULL)
		return (NULL);

	mib[0] = CTL_KERN;
#if defined(__FreeBSD__) || defined(__DragonFly__)
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_ARGS;
	mib[3] = pid;
#elif defined(__NetBSD__)
	mib[1] = KERN_PROC_ARGS;
	mib[2] = pid;
	mib[3] = KERN_PROC_ARGV;
#endif

	if (sysctl(mib, 4, buf, &len, NULL, 0) < 0)
		goto bad;
	buf[len] = '\0';

	argc = memnchr(buf, '\0', len);
	argv = malloc((argc + 1) * sizeof(char *));
	if (argv == NULL)
		goto bad;

#if !defined(__FreeBSD__)
	if (buf[0] != '/') {
		argv[0] = kinfo_getpathname(pid);
		if (argv[0] != NULL) {
			if (!strcmp(xbasename(buf), xbasename(argv[0]))) {
				off += strlen(buf) + 1;
				i++;
			} else
				free(argv[0]);
		}
	}
#endif

	for (; i < argc; i++) {
		argv[i] = strdup(buf + off);
		if (argv[i] == NULL)
			goto bad;
		off += strlen(argv[i]) + 1;
	}
	argv[argc] = NULL;

	free(buf);
	return (argv);

bad:
	free_argv(argv);
	free(buf);
	return (NULL);
}
