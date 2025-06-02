#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ip_packet.h"

void raw_packet_builder(PacketStruct * packet_struct){
    base_packet_builder(packet_struct);
    packet_struct->version = IPV4_VERSION;
    packet_struct->tos = 0;
    packet_struct->frag_offset = 0;
    packet_struct->protocol = EXPERIMENTAL_PROTOCOL;
    packet_struct->ip_options_length = 0;
   
    packet_struct->ihl = 5 + packet_struct->ip_options_length;
}


PacketStruct * create_packet(const char * payload, const char * src_ip, const char * dst_ip, void (*packet_builder)(PacketStruct*)){
    PacketStruct * packet_struct = (PacketStruct*)calloc(1, sizeof(PacketStruct));
    packet_builder(packet_struct);
   
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

int main() {
    PacketStruct * builder = create_packet("HELLO SAM\n", "192.168.1.170", "192.168.1.170", raw_packet_builder);

     IPPacket * packet = pack_packet(builder);
     if (packet == NULL) {
         printf("Failed to build packet\n");
         return 1;
     } else{
         packet_print_debug(packet);
     }
     packet_free(packet);
     return 0;
 }
