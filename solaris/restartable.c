#include <sys/types.h>
#include <err.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <libproc.h>
#define _KERNEL
#include <sys/procfs.h>

#define VERSION	"2.3.4"

static int verbose;

static int
compare_pids(const void *a, const void *b) {
	return *(const int *)a - *(const int *)b;
}

static void
parse_psinfo(int pid) {
	struct passwd *pwd;
	char *user = "-";
	psinfo_t psinfo;

	if (proc_get_psinfo(pid, &psinfo) == -1) {
		warn("%d", pid);
		return;
	}

	if ((pwd = getpwuid(psinfo.pr_uid)) != NULL)
		user = pwd->pw_name;
	printf("%d\t%d\t%d\t%s\t%s\n", psinfo.pr_pid, psinfo.pr_ppid, psinfo.pr_uid, user, psinfo.pr_fname);
	if (verbose)
		printf("\t%s\n", psinfo.pr_psargs);
}

/*
 * Solaris mounts an optimized /lib/libc.so.1 at boot time
 * so it always shows on /proc/<pid>/path/ as a brokem symlink
 */
static int
is_libc_so(int pid, uintptr_t addr) {
	struct ps_prochandle *Pr;
	char path[PATH_MAX];
	char pidstr[256];
	ssize_t len;
	int gcode;

	(void)snprintf(pidstr, sizeof(pidstr), "%d", pid);

	if ((Pr = proc_arg_grab(pidstr, PR_ARG_PIDS, PGRAB_RDONLY, &gcode)) == NULL) {
		warnx("%s: %s", pidstr, Pgrab_error(gcode));
		return 0;
	}

	path[0] = '\0';
	if (Pobjname_resolved(Pr, addr, path, sizeof(path)) != NULL)
		if ((len = resolvepath(path, path, sizeof(path))) > 0)
			path[len] = '\0';

	(void)Prelease(Pr, 0);
	return (!strcmp(path, "/lib/libc.so.1"));
}

static void
print_proc(int pid) {
	char linkPath[PATH_MAX];
	char link[PATH_MAX];
	char procPid[256];
	int procFd, mapFd;
	prmap_t entry;

	(void)snprintf(procPid, sizeof(procPid), "/proc/%d", pid);
	if ((procFd = open(procPid, O_RDONLY | O_DIRECTORY)) == -1)
		return;

	if ((mapFd = openat(procFd, "map", O_RDONLY)) == -1) {
		warn("%d", pid);
		close(procFd);
		return;
	}

	while (read(mapFd, &entry, sizeof(entry)) == sizeof(entry)) {
		/* Skip anonymous mappings */
		if (entry.pr_mflags & MA_ANON)
			continue;
		/* Skip non-executable mappings */
		if (!(entry.pr_mflags & MA_EXEC)) 
			continue;
		/* Solaris doesn't have w^x, so skip writable to avoid duplicate entries */
		if (entry.pr_mflags & MA_WRITE)
			continue;

		(void)snprintf(linkPath, sizeof(linkPath), "path/%s", entry.pr_mapname);
		if ((readlinkat(procFd, linkPath, link, sizeof(link)) == -1 &&
		    !is_libc_so(pid, entry.pr_vaddr)) ||
		    !strncmp(link, "/proc/", sizeof("/proc"))) {
			parse_psinfo(pid);
			break;
		}
	}

	(void)close(mapFd);
	(void)close(procFd);
}

static void
print_all(void) {
	DIR *dir;
	struct dirent *entry;
	int *pids = NULL;
	struct stat st;
	unsigned int i, nproc;

	/* Get the number of processes through st_nlink */
	if (stat("/proc", &st) == -1)
		err(1, "/proc");

	pids = (int *) malloc(st.st_nlink * sizeof(int));
	if (pids == NULL)
		err(1, "malloc");

	dir = opendir("/proc");
	if (dir == NULL)
		err(1, "/proc");

	for (nproc = 0; nproc < st.st_nlink; nproc++) {
		if ((entry = readdir(dir)) == NULL)
			break;
		pids[nproc] = atoi(entry->d_name);
	}

	(void)closedir(dir);

	qsort(pids, ++nproc, sizeof(int), compare_pids);

	for (i = 0; i < nproc; i++)
		print_proc(pids[i]);

	free(pids);
}

static void
usage(void) {
	fprintf(stderr, "Usage: %s [-v]\n", getprogname());
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

	printf("PID\tPPID\tUID\tUser\tCommand\n");
	print_all();

	return (0);
}
