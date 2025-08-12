"""
pmu {

	riscv,event-to-mhpmcounters = <0x1 0x1 0x7fff9
					0x2 0x2 0x7fffc
					0x10019 0x10019 0x7fff8
					0x1001b 0x1001b 0x7fff8
					0x10021 0x10021 0x7fff8>;
	compatible = "riscv,pmu";
};
"""

print("\t\triscv,event-to-mhpmcounters =")

f = open("x730_hpm")
for line in f.readlines():
	spl = line.split()
	event_id = spl[0]
	print("\t\t\t<%s %s 0x78>," % (event_id, event_id))
print(";")
