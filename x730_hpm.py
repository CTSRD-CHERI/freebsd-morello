"""
mhpmcounters {
        mhpmcounter = {
                id = 3;
                name = 'eee';
                event_id = 33;
                enabled = true;
        }
        mhpmcounter = {
                id = 4;
                name = 'vvv';
                event_id = 22;
                enabled = true;
        }
}
"""

print("# ");
print("# Codasip X730 event id table.");
print("# Counter IDs available: 3 to 6.")
print("# ");

print("mhpmcounters {")

f = open("x730_hpm")
for line in f.readlines():
	spl = line.split()
	event_id = spl[0]
	name = ' '.join(spl[1:])
	print("\tmhpmcounter = {")
	print("\t\tid = 3;")
	print("\t\tname = '%s';" % name)
	print("\t\tevent_id = %s;" % event_id)
	print("\t\tenabled = false;")
	print("\t}")

print("}")
