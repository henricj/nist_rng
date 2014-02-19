CPPFLAGS+=        -I${.CURDIR}/../../include

CDIAGFLAGS=     -Wall
CDIAGFLAGS+=    -Wpointer-arith
CDIAGFLAGS+=    -Wno-uninitialized
CDIAGFLAGS+=    -Wstrict-prototypes
CDIAGFLAGS+=    -Wmissing-prototypes
CDIAGFLAGS+=    -Wunused
CDIAGFLAGS+=    -Wsign-compare
CDIAGFLAGS+=    -Wbounded
CDIAGFLAGS+=    -Wshadow

.include <bsd.obj.mk>

.if exists(${.CURDIR}/../../lib/${__objdir})
LDADD+=         -L${.CURDIR}/../../lib/${__objdir} -lnist_drbg
DPADD+=         ${.CURDIR}/../../lib/${__objdir}/libnist_drbg.a
.else
LDADD+=         -L${.CURDIR}/../../lib -lnist_drbg
DPADD+=         ${.CURDIR}/../../lib/libnist_drbg.a
.endif

