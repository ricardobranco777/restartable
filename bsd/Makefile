OPSYS:sh = uname

PROG= restartable
WARNS= 3
CFLAGS+= -O2
.if ${OPSYS} == "OpenBSD"
CFLAGS+= -Wall -Wmissing-prototypes -Wno-uninitialized -Wstrict-prototypes
LDADD+= -lkvm
DPADD+= ${LIBKVM}
.else
LDFLAGS= -lutil
.endif
.if ${OPSYS} != "DragonFly"
.endif
SRCS= restartable.c
HDRS= extern.h
.if ${OPSYS} != "OpenBSD"
SRCS+= kinfo_getargv.c util.c
.endif

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
