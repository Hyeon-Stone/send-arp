//#pragma once
#include <stdint.h>
#include <pcap.h>
#pragma pack(push, 1)
typedef struct{
    uint8_t Dst_mac[6];
    uint8_t Src_mac[6];
    uint16_t type;
}EthHdr;
typedef struct{
    uint8_t Hl:4;       // Follow Bit Order (Not Byte Order)
    uint8_t Verison:4;
    uint8_t Tos;
    uint16_t Total_len;
    uint16_t Id;
    uint16_t Frag_off;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t Check;
    uint32_t Src_ip;
    uint32_t Des_ip;
}IpHdr;
typedef struct{
    uint16_t Src_port;
    uint16_t Des_port;
    uint32_t Seq_num;
    uint32_t Ack_num;
    uint8_t Reverse_NG:4;   // Follow Bit Order (Not Byte Order)
    uint8_t Offset:4;
    uint8_t Flag;
    uint16_t Window;
    uint16_t Checksum;
    uint16_t Urgent;
}TCPHdr;

typedef struct{
    uint16_t Hw_type;
    uint16_t Proto_type;
    uint8_t Hw_addr_len;
    uint8_t Proto_addr_len;
    uint16_t Opcode;
    uint8_t Src_mac[6];
    uint32_t Src_ip;
    uint8_t Tag_mac[6];
    uint32_t Tag_ip;
}ArpHdr;

typedef struct{
    EthHdr eth_;
    ArpHdr arp_;
}EthArpPacket;
#pragma pack(pop)

void PrintMAC(uint8_t *mac);

void PrintIP(uint32_t ip);

uint32_t Str2A(char *ip_string);

uint32_t GetMyIp(char *dev);

void  GetMyMac(char* dev, uint8_t *mac);

EthArpPacket MakeArpRequest(uint32_t source_ip, uint8_t* source_mac, uint32_t target_ip);

EthArpPacket MakeArpInfect(uint32_t gateway_ip, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac);

void CapArpReply(pcap_t* handle, uint32_t target_ip, uint8_t* target_mac);

void SendRequest(pcap_t* handle, uint32_t source_ip, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac);

void SendInfect(pcap_t* handle, uint8_t* source_mac, uint32_t target_ip, uint8_t* target_mac, uint32_t gateway_ip);