#include <sys/types.h>

int memnchr(const void *, int, size_t);
void free_argv(char **);
char **kinfo_getargv(pid_t pid);

#ifdef __NetBSD__
#define kinfo_proc kinfo_proc2
#endif

#if defined(__NetBSD__) || defined(__DragonFly__)
struct kinfo_proc *kinfo_getallproc(int *);
#endif

#ifdef __DragonFly__
struct kinfo_vmentry {
	int	kve_type;
	int	kve_protection;
	char	kve_path[4096];
};

struct kinfo_vmentry *kinfo_getvmmap(pid_t, int *);

#define KVME_TYPE_VNODE	2
#define KVME_PROT_EXEC	4
#endif /* __DragonFly__ */
