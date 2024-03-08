OPSYS:sh = uname

PROG= restartable
WARNS= 3
CFLAGS+= -O2
.if ${OPSYS} != "DragonFly"
LDFLAGS= -lutil
.endif
SRCS= restartable.c kinfo_getargv.c util.c
HDRS= extern.h

BINDIR= /usr/local/bin

.if ${OPSYS} == "NetBSD"
BINDIR= /usr/pkg/bin
SRCS+= kinfo_getallproc.c
.elif ${OPSYS} == "DragonFly"
SRCS+= kinfo_getallproc.c kinfo_getvmmap.c
.endif

MK_DEBUG_FILES= no
MAN=

.include <bsd.prog.mk>
