#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "ip_packet_builder.h"

// THE PURPOSE OF THIS MODULE IS TO IMPLEMENT AND SEND
// A RAW (NO UDP/TCP) IP PACKET ALONG THE NETWORK.
// THIS MEANS THAT WE CANNOT USE ANY OF THE IANA DEFINED
// PROTOCOL NUMBERS (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#Internet_Assigned_Numbers_Authority)

void raw_packet_builder(PacketBuilder * packet_struct, const char * dest_ip_string, const char * source_ip_string){
    base_packet_builder(packet_struct, dest_ip_string, source_ip_string);

    packet_struct->version = IPV4_VERSION;
    packet_struct->tos = 0;
    packet_struct->frag_offset = 0;
    packet_struct->protocol = EXPERIMENTAL_PROTOCOL;
    packet_struct->ip_options_length = 0;
   
    packet_struct->ihl = 5 + packet_struct->ip_options_length;
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

    return 0;
}


int main() {
    // IMPORTANT: CHECK YOUR IP ADDRESS EVERYTIME YOU RUN THIS
    char dest_ip[] = "172.17.0.1";//"192.168.1.170";
    char source_ip[] = "172.17.0.1";//192.168.1.170";
    PacketBuilder * builder = create_packet("HELLO SAM\n", dest_ip, source_ip, raw_packet_builder);
    IPPacket * packet = pack_packet(builder);
    packet_builder_free(builder);
    
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
