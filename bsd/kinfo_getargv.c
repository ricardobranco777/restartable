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

void
free_argv(char **argv)
{
	char **argvp = argv;

	while (*argvp != NULL) {
		free(*argvp);
		argvp++;
	}

	free(argv);
}

char **
kinfo_getargv(pid_t pid)
{
	char *buf = NULL;
	char **argv;
	int mib[4];
	int i, argc;
	size_t off = 0, len = ARG_MAX;

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

	for (i = 0; i < argc; i++) {
		argv[i] = strdup(buf + off);
		if (argv[i] == NULL) {
			free_argv(argv);
			goto bad;
		}
		off += strlen(argv[i]) + 1;
	}
	argv[argc] = NULL;

	free(buf);
	return (argv);

bad:
	free(buf);
	return (NULL);
}
