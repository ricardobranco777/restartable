OPSYS:sh = uname

PROG= restartable
WARNS= 3
CFLAGS+= -O2
.if ${OPSYS} == "OpenBSD"
CFLAGS+= -Wall -Wmissing-prototypes -Wno-uninitialized -Wstrict-prototypes
LDADD+= -lkvm
DPADD+= ${LIBKVM}
.else
LDFLAGS= -lutil -lkvm
.endif
SRCS= restartable.c
.if ${OPSYS} == "DragonFly"
SRCS+= kinfo_getvmmap.c
.endif
HDRS= extern.h

.if ${OPSYS} == "NetBSD"
BINDIR= /usr/pkg/bin
.else
BINDIR= /usr/local/bin
.endif

MK_DEBUG_FILES= no
MAN=

.include <bsd.prog.mk>
