make -j10 TARGET=riscv buildkernel || exit 1

cp /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/GENERIC/kernel /home/br/dev/cva6-tools/gdb-freebsd/kernel_only
