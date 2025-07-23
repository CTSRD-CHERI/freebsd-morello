PROG_CXX=	hwc
MAN=

CFLAGS+= -I${SRCTOP}/sys

LIBADD=	xo

SRCS=	hwc.c			\
	hwc_process.c

.if ${MACHINE_CPUARCH} == "riscv"
.endif

.include <bsd.prog.mk>
