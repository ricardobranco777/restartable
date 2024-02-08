OPSYS:sh = uname

PROG= restartable
WARNS= 3
CFLAGS+= -O2
.if ${OPSYS} == "FreeBSD"
LDFLAGS= -lprocstat
.elif ${OPSYS} == "NetBSD"
LDFLAGS= -lkvm -lutil
.endif

MK_DEBUG_FILES= no
MAN=

.include <bsd.prog.mk>
