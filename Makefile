LDLIBS=-lpcap

all: send-arp

arphdr.o: arphdr.h arphdr.cpp

ethhdr.o: ethhdr.h ethhdr.cpp

send.o: ethhdr.h arphdr.h send.h send.cpp

send-arp: main.o arphdr.o ethhdr.o send.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o
clean:
	rm -f send-arp-test *.o

