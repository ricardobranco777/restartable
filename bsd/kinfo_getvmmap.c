#include <sys/types.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

static char *
procmap(pid_t pid)
{
	ssize_t size = 65536;
	char *buf = NULL;
	char path[64];
	ssize_t n;
	int fd;

	(void) snprintf(path, sizeof(path), "/proc/%d/map", pid);
	if ((fd = open(path, O_RDONLY)) == -1)
		return (NULL);

	if ((buf = calloc(1, size)) == NULL)
		goto bad;

	/* This file must be read in one go */
	while (1) {
		n = read(fd, buf, size);
		if ((n == -1 && errno == EFBIG) || n == size) {
			size <<= 1;
			if (size < 0)
				errc(1, EOVERFLOW, "map too large for pid %d", pid);
			free(buf);
			if ((buf = calloc(1, size)) == NULL)
				goto bad;
			if (lseek(fd, 0, SEEK_SET) == -1)
				goto bad;
		}
		else if (n == -1)
			goto bad;
		else
			break;
	}

	(void) close(fd);
	return (buf);

bad:
	if (buf != NULL)
		free(buf);
	(void) close(fd);
	return (NULL);
}

/* Minimal kinfo_getvmmap */
struct kinfo_vmentry *
kinfo_getvmmap(pid_t pid, int *cntp)
{
	struct kinfo_vmentry *kiv;
	struct stat st;
	char prot[4], type[10];
	char *buf;

	if ((buf = procmap(pid)) == NULL)
		return (NULL);

	*cntp = memnchr(buf, '\n', strlen(buf));
	kiv = calloc(*cntp, sizeof(struct kinfo_vmentry));
	if (kiv == NULL)
		goto bad2;

	char *line = buf;
	for (int i = 0; i < *cntp; i++) {
		char *token = strsep(&line, "\n");
		if (token == NULL)
			break;
		/*
		 * Parse lines like this:
		 * 0x0000000000400000 0x0000000000403000 -1 -1 0xfffff80119599400 r-x 2 0 0x0000 COW NC vnode /bin/cat
		 */
		(void) sscanf(token, "%*x %*x %*d %*d %*x %3s %*d %*d %*x %*s %*s %10s %4096[^\n]", prot, type, kiv[i].kve_path);
		kiv[i].kve_protection = (prot[2] == 'x') ? KVME_PROT_EXEC : 0;
		if (!strcmp(type, "vnode")) {
			kiv[i].kve_type |= KVME_TYPE_VNODE;
			if (lstat(kiv[i].kve_path, &st) < 0)
				kiv[i].kve_path[0] = '\0';
		}
	}

	return kiv;

bad2:
	free(buf);
	return (NULL);
}
