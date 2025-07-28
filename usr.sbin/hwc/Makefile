PROG_CXX=	hwc
MAN=

CFLAGS+= -I${SRCTOP}/contrib/libucl/include
CFLAGS+= -I${SRCTOP}/sys

LIBADD=	xo ucl

SRCS=	hwc.c			\
	hwc_pmu.c		\
	hwc_process.c

.if ${MACHINE_CPUARCH} == "riscv"
.endif

.include <bsd.prog.mk>
