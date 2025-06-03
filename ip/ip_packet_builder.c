#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <regex.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ip_packet_builder.h"

// Configuration constants
#define DEFAULT_TTL 64

IPPacket * pack_packet(PacketBuilder *packet_struct) {
    IPPacket * packet = (IPPacket *) calloc(1, sizeof(IPPacket));
    packet->dest_ip = packet_struct->dest_ip;
    packet->source_ip = packet_struct->source_ip;
    packet->header_length = packet_struct->ihl * 4;
    packet->total_length = packet->header_length + (packet_struct->payload ? strlen(packet_struct->payload) : 0);
    packet->data = calloc(packet->total_length, sizeof(uint8_t));
    if (!packet->data) {return NULL;}

    uint8_t *p = packet->data;
    p[0] = (packet_struct->version << 4) | packet_struct->ihl;
    p[1] = packet_struct->tos;
    *(uint16_t *)(p + 2) = htons(packet->total_length);
    *(uint16_t *)(p + 4) = htons(packet_struct->identification);
    *(uint16_t *)(p + 6) = htons(packet_struct->frag_offset);
    p[8] = packet_struct->ttl;
    p[9] = packet_struct->protocol;
    *(uint32_t *)(p + 12) = packet_struct->source_ip;
    *(uint32_t *)(p + 16) = packet_struct->dest_ip;

    for (int option = 0; option < packet_struct->ip_options_length; ++option){
        *(uint32_t *)(p + 20 + 4 * option) = (packet_struct->ip_options)[option];
    }
    // CHECKSUM LAST
    *(uint16_t *)(p + 10) = calc_checksum(p, packet->header_length);

    if (packet_struct->payload) {
        memcpy(p + packet->header_length, packet_struct->payload, strlen(packet_struct->payload));
    }

    return packet;
}


// Debugging (separated for SRP)
void packet_print_debug(const IPPacket *packet) {
    printf("Generated IP Packet:\n");
    printf("  Version: %u, IHL: %u (Header Size: %d bytes)\n", packet->data[0] >> 4, packet->data[0] & 0x0F, packet->header_length);
    printf("  Total Length: %u bytes\n", packet->total_length);
    printf("  Protocol: %u\n", packet->data[9]);
    printf("  Checksum: 0x%04x\n", *(uint16_t *)(packet->data + 10));
    printf("Hex dump of the first %d bytes (IP Header):\n", packet->header_length);
    for (int i = 0; i < packet->header_length; i++) {
        printf("%02X ", packet->data[i]);
        if ((i + 1) % 4 == 0) printf(" ");
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

PacketBuilder * create_packet(const char * payload, const char * src_ip, const char * dst_ip, void (*packet_builder)(PacketBuilder*, const char *, const char *)){
    PacketBuilder * packet_struct = (PacketBuilder*)calloc(1, sizeof(PacketBuilder));
    packet_builder(packet_struct, dst_ip, src_ip);
   
    uint32_t src=ip_string_to_address(src_ip), dst=ip_string_to_address(dst_ip);
    if (src < SUCCESS ||
        dst < SUCCESS) {
        printf("Invalid IP address\n");
        return NULL;
    }

    packet_struct->source_ip = src;
    packet_struct->dest_ip = dst;
    packet_struct->payload = strdup(payload);

    return packet_struct;
}


void base_packet_builder(PacketBuilder * packet_struct, const char * dest_ip_string, const char * source_ip_string){
    packet_struct->dest_ip = ip_string_to_address(dest_ip_string);
    packet_struct->source_ip = ip_string_to_address(source_ip_string);
    packet_struct->identification = rand() % 65536;
    packet_struct->ttl = DEFAULT_TTL;
    packet_struct->payload = NULL;
};


