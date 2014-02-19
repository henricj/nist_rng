
.PATH:		${.CURDIR}/..

LIB=	nist_drbg
SRCS=				\
	diffusion.c 		\
	dump.c 			\
	nist_aes_padlock.c 	\
	nist_ctr_drbg.c 	\
	rijndael.c 		\
	runtime.c

DEBUGLIBS= no
NOPROFILE= yes
NOPIC=	yes

CPPFLAGS+= -I${.CURDIR}/../include
CFLAGS+= -Wall

install:
	@echo -n

.include <bsd.lib.mk>
