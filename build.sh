A=CONF
if [ "$1" = "fast" ]; then
        A=FAST
else
    make -j24 TARGET=riscv KERN${A}=GENERIC cleankernel
fi

make -j24 TARGET=riscv KERN${A}=GENERIC buildkernel || exit 1

riscv64-unknown-freebsd15.0-objcopy -O binary /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/GENERIC/kernel /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/GENERIC/kernel.bin

scp /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/usr.sbin/hwc/hwc 10.4.0.2:~/

echo "/usr/bin/cpuset -l 0 ./hwc -f qemu /usr/bin/uname"
