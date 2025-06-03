#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "ip_packet_unpacking.h"

IPPacket * unpack_packet(uint8_t * buffer, int bytes_recieved){
    uint8_t ip_header_length = buffer[0] & 0x0F;
    uint8_t version = buffer[0] & 0xF0;
    uint16_t total_length = ntohs(*(uint16_t *)(buffer + 2));
    uint16_t packet_id = ntohs(*(uint16_t *)(buffer + 4));
    /*printf("ip header reported total length %d, bytes recieved %d\n", total_length, bytes_recieved); */ 
    // if no fragmentation, you can assert total_length == bytes_recieved
    uint32_t src_ip = ntohl(*(uint32_t *) (buffer + 12));
    uint32_t dst_ip = ntohl(*(uint32_t *) (buffer + 16));
    char * payload_slice = (char *) (buffer + ip_header_length * 4);
    IPPacket * ip_packet = (IPPacket *) calloc(1, sizeof(IPPacket));
    ip_packet->total_length = total_length;
    ip_packet->header_length = ip_header_length;
    ip_packet->dest_ip = dst_ip;
    ip_packet->source_ip = src_ip;
    ip_packet->data = (uint8_t *) strdup(payload_slice);
    printf("Unpacked packet payload: %s\n", ip_packet->data);
    return ip_packet;



    // Bonus project: extend packet unpacking to 
    // collect and combine fragmentation.
    // This would likely require some form of state/heap memory

    /*uint16_t fragmentation = ntohs(*(uint16_t *)(buffer + 6));*/
    /*if (fragmentation & 0x20){*/
    /*    // more fragments to come with same ID*/
    /*    collect_fragments(*/
    /*} else {*/
    /*    printf("Unpacked packet payload: %s\n", ip_packet->data);*/
    /*    return ip_packet;*/
    /*}*/

}
