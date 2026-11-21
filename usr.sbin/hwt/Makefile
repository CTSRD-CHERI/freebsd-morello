PROG=	hwt
MAN=		hwt.8

CFLAGS+= -I${SRCTOP}/lib/libpmcstat -I${SRCTOP}/sys -I${SRCTOP}/usr.sbin/hwt

LIBADD= elf pmcstat xo util

SRCS=	hwt.c			\
	hwt_fmt.c		\
	hwt_elf.c		\
	hwt_process.c		\
	hwt_record.c		\
	libpmcstat_stubs.c

.if ${MACHINE_CPUARCH} == "aarch64"
SRCS+=	coresight/hwt_coresight.c
SRCS+=	spe/hwt_spe.c
LIBADD+= opencsd
.elif ${MACHINE_CPUARCH} == "amd64"
SRCS+= 	pt/hwt_pt.c		\
	pt/hwt_pt_decode.c	\
	pt/hwt_pt_dump.c	\
	pt/hwt_pt_fmt.c
LIBADD+= ipt
.endif

.include <bsd.prog.mk>
