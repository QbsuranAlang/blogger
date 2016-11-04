
CC = gcc

PROGS = list-devices default-device

PCAP_DIR = /usr/local/opt/libpcap
CFLAGS = -I$(PCAP_DIR)/include -Wall -std=gnu99
LIBS = -lpcap
LDFLAGS = -L$(PCAP_DIR)/lib $(LIBS)

all: ${PROGS}

clean:
	rm -f ${PROGS}
