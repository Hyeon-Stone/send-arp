LDLIBS=-lpcap

all: send-arp

send-arp: main.o hdr.c hdr.h
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f *.o

