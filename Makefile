LDLIBS=-lpcap

all : send-arp

send-arp: main.o arphdr.h arphdr.cpp  ethhdr.h ethhdr.cpp  send.h send.cpp
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f *.o

