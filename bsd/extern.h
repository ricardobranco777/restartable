#ifdef __DragonFly__
#include <sys/types.h>

struct kinfo_vmentry {
	int	kve_type;
	int	kve_protection;
	char	kve_path[4096];
};

struct kinfo_vmentry *kinfo_getvmmap(pid_t, int *);

#define KVME_TYPE_VNODE	2
#define KVME_PROT_EXEC	4
#endif /* __DragonFly__ */
