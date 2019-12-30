all:
	gcc -o read_packet read_packet.c -lpcap
claen:
	rm -f read_packet