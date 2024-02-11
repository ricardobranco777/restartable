
void free_argv(char **);
char **kinfo_getargv(pid_t pid);

#ifdef __NetBSD__
#define kinfo_proc kinfo_proc2
struct kinfo_proc *kinfo_getallproc(int *);
#endif
