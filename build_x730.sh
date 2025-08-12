A=CONF
if [ "$1" = "fast" ]; then
	A=FAST
else
	make -j24 TARGET=riscv KERN${A}=X730 cleankernel
fi

make -j24 KERN${A}=X730 TARGET=riscv buildkernel || exit 1

cp /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/X730/kernel /tftpboot/root/boot/kernel

cp /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/sys/X730/kernel /tftpboot/codasip_vcu118/
riscv64-unknown-freebsd15.0-objcopy -O binary /tftpboot/codasip_vcu118/kernel /tftpboot/codasip_vcu118/kernel.bin

# echo fdt move \$fdt_addr 0x88000000
# echo "setenv serverip 10.5.0.1; setenv ipaddr 10.5.0.93; tftp 0x82000000 codasip_vcu118/kernel.bin; go 0x82000000 0 0"

# echo "fdt move \$fdt_addr 0x88000000; setenv serverip 10.5.0.1; setenv ipaddr 10.5.0.93; tftp 0x82000000 codasip_vcu118/kernel.bin; go 0x82000000 0 0"
# echo "fdt move \$fdt_addr 0x88000000; setenv serverip 10.5.0.1; setenv ipaddr 10.5.0.93; tftp 0x82000000 codasip_vcu118/loader_lua.efi; bootefi 0x82000000 0x88000000"

echo "setenv serverip 10.5.0.1; setenv ipaddr 10.5.0.93; tftp 0x88000000 codasip_vcu118/x730-mp1-hobgoblin-vcu118.dtb; tftp 0x82000000 codasip_vcu118/loader_lua.efi; bootefi 0x82000000 0x88000000"

# echo fatload mmc 0 0x82000000 loader_lua.efi

# flash update
# setenv serverip 10.5.0.1; setenv ipaddr 10.5.0.93; tftp 0x88000000 codasip_vcu118/flash.bin
# fatwrite mmc 0 0x88000000 flash.bin $filesize

scp /usr/obj/usr/home/br/dev/freebsd/riscv.riscv64/usr.sbin/hwc/hwc 10.5.0.151:~/
