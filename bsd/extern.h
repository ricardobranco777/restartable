
void free_argv(char **);
char **kinfo_getargv(pid_t pid);

#ifdef __NetBSD__
struct kinfo_proc *kinfo_getallproc(int *);
#endif
