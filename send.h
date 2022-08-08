#include <stdint.h>
#include <pcap.h>
#include "arphdr.h"
#include "ethhdr.h"
typedef struct{
    EthHdr eth_;
    ArpHdr arp_;
}EthArpPacket;

void PrintMAC(char* msg, uint8_t *mac);

void PrintIP(char* msg, uint32_t ip);

uint32_t Str2A(char *ip_string);

uint32_t GetMyIp(char *dev);

void  GetMyMac(char* dev, uint8_t *mac);

EthArpPacket MakeArpRequest(uint32_t source_ip, uint8_t* source_mac, uint32_t target_ip);

EthArpPacket MakeArpInfect(uint32_t gateway_ip, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac);

void CapArpReply(pcap_t* handle, uint32_t target_ip, uint8_t* target_mac);

void SendRequest(pcap_t* handle, uint32_t source_ip, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac);

void SendInfect(pcap_t* handle, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac, uint32_t gateway_ip);
