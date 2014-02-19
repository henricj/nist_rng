PROG=	c7random
SRCS=   c7random.c nist_rbg.c

NOMAN=  noman

CFLAGS+= -Wall -Werror -O2 -fstrict-aliasing -fomit-frame-pointer -march=c3
LDSTATIC=       ${STATIC}

.include <bsd.prog.mk>
