/* Minimal implementation of kinfo_getvmmap for DragonflyBSD */

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

static int
count_char(const void *p, int c, size_t len)
{
	int n = 0;

	for (size_t i = 0; i < len; i++)
		if (*((const unsigned char *)p + i) == c)
			n++;

	return n;
}

static char *
procmap(pid_t pid)
{
	ssize_t size = 65536;
	char *buf = NULL;
	char path[64];
	ssize_t n;
	int fd;

	(void)snprintf(path, sizeof(path), "/proc/%d/map", pid);
	if ((fd = open(path, O_RDONLY)) == -1)
		return (NULL);

	/* This file must be read in one go */
	while (1) {
		if ((buf = calloc(1, size)) == NULL)
			goto bad;
		n = read(fd, buf, size);
		if ((n == -1 && errno == EFBIG) || n == size) {
			size <<= 1;
			if (size < 0)
				errc(1, EFBIG, "map too large for pid %d", pid);
			if (lseek(fd, 0, SEEK_SET) == -1)
				goto bad;
			free(buf);
		}
		else if (n == -1)
			goto bad;
		else
			break;
	}

	(void)close(fd);
	return (buf);

bad:
	if (buf != NULL)
		free(buf);
	(void)close(fd);
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

	*cntp = count_char(buf, '\n', strlen(buf));
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
		(void)sscanf(token,
		    "%*x %*x %*d %*d %*x %3s %*d %*d %*x %*s %*s %10s %4096[^\n]",
		    prot, type, kiv[i].kve_path);
		kiv[i].kve_protection = (prot[2] == 'x') ? KVME_PROT_EXEC : 0;
		if (!strcmp(type, "vnode")) {
			kiv[i].kve_type |= KVME_TYPE_VNODE;
			if (kiv[i].kve_path[0] != '/' ||
			    lstat(kiv[i].kve_path, &st) < 0)
				kiv[i].kve_path[0] = '\0';
		}
	}

	free(buf);
	return (kiv);

bad2:
	free(buf);
	return (NULL);
}
