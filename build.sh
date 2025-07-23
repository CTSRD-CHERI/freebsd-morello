A=CONF
if [ "$1" = "fast" ]; then
        A=FAST
else
    make -j24 TARGET=riscv KERN${A}=GENERIC cleankernel
fi

make -j24 TARGET=riscv KERN${A}=GENERIC buildkernel || exit 1
