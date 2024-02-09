OPSYS:sh = uname

PROG= restartable
WARNS= 3
CFLAGS+= -O2
LDFLAGS= -lutil
SRCS= restartable.c kinfo_getargv.c
HDRS= extern.h

.if ${OPSYS} == "NetBSD"
SRCS+= kinfo_getallproc.c
.endif

MK_DEBUG_FILES= no
MAN=

.include <bsd.prog.mk>
