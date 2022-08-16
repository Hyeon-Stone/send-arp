#include <stdint.h>
#include <pcap.h>
#include "arphdr.h"
#include "ethhdr.h"

enum: int {
    REQ = 0,
    RPlY = 1,
    INFECT = 2
};

typedef struct{
    EthHdr eth_;
    ArpHdr arp_;
}EthArpPacket;

void PrintMAC(char* msg, uint8_t *mac);

void PrintIP(char* msg, uint32_t ip);

uint32_t Str2A(char *ip_string);

uint32_t GetMyIp(char *dev);

void  GetMyMac(char* dev, uint8_t *mac);

EthArpPacket MakeArp(int make_type ,uint32_t source_ip, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac);

void CapArpReply(pcap_t* handle, uint32_t target_ip, uint8_t* target_mac);

void Send(int make_type, pcap_t* handle, uint32_t source_ip, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac);
