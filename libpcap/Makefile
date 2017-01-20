
CC = gcc

PROGS = list-devices \
	default-device \
	capture-pcap_loop-and-pcap_dispatch \
	capture-pcap_next_ex \
	save-to-file \
	read-from-file \
	dump-ethernet \
	dump-arp \
	dump-ip \
	dump-tcp-and-udp \
	dump-icmp \
	send-a-frame \
	offline-filter \
	list-data-link-type \
	get-stat \

PCAP_DIR = /usr/local/opt/libpcap
CFLAGS = -I$(PCAP_DIR)/include -Wall -std=gnu99
LIBS = -lpcap
LDFLAGS = -L$(PCAP_DIR)/lib $(LIBS)

all: ${PROGS}

clean:
	rm -f ${PROGS}
	rm -f saved.pcap
