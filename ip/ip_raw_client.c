#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ip_packet.h"

void raw_packet_builder(PacketStruct * packet_struct, const char * dest_ip_string, const char * source_ip_string){
    base_packet_builder(packet_struct, dest_ip_string, source_ip_string);

    packet_struct->version = IPV4_VERSION;
    packet_struct->tos = 0;
    packet_struct->frag_offset = 0;
    packet_struct->protocol = EXPERIMENTAL_PROTOCOL;
    packet_struct->ip_options_length = 0;
   
    packet_struct->ihl = 5 + packet_struct->ip_options_length;
}


PacketStruct * create_packet(const char * payload, const char * src_ip, const char * dst_ip, void (*packet_builder)(PacketStruct*, const char *, const char *)){
    PacketStruct * packet_struct = (PacketStruct*)calloc(1, sizeof(PacketStruct));
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

int send_network_level_packet(IPPacket * packet){
    // NOT SURE IF WE SHOULD USE THE STRATEGY PATTERN:
    // THE LOGIC OF USING A SOCKET TO INTERFACE WITH NETWORK LAYER 
    // IS PRETTY UNIQUE TO THIS PROJECT
    int dest_ip = packet->dest_ip;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {printf("ERROR CREATING SOCKET\n"); return -1;}
    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0){
        printf("FAILED TO SET IP Header included option\n");
        return -2;
    }
    struct sockaddr_in dest_address;
    dest_address.sin_family = AF_INET;
    dest_address.sin_port = 0; // not used
    dest_address.sin_addr.s_addr = packet->dest_ip;


    // --- Send the Packet ---
    if (sendto(sock, packet->data, packet->total_length, 0,
               (struct sockaddr *)&dest_address, sizeof(dest_address)) < 0) {
        perror("Failed to send packet");
    } else {
        printf("Packet sent successfully!\n");
    }

    // --- Clean Up ---
    close(sock);
    free(packet);

    return 0;
}


int main() {
    char * dest_ip = "192.168.1.170";
    char * source_ip = "192.168.1.170";
    PacketStruct * builder = create_packet("HELLO SAM\n", dest_ip, source_ip, raw_packet_builder);

    IPPacket * packet = pack_packet(builder);
    if (packet == NULL) {
        printf("Failed to build packet\n");
        return 1;
    } else{
        packet_print_debug(packet);
    }

    send_network_level_packet(packet);
    packet_free(packet);
    return 0;
}
