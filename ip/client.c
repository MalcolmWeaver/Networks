#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <regex.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ip_datagram_header.h"

#define EXPERIMENTAL_PROTOCOL 253


// TODO: Test and fix send_network_level_packet
int send_network_level_packet(uint8_t * packet, int packet_size, char * dest_ip_string){
    int dest_ip = human_readable_to_bits(dest_ip_string);
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
    dest_address.sin_addr.s_addr = dest_ip;

    printf("  Protocol: %u (Custom)\n", 253);

    // --- Send the Packet ---
    if (sendto(sock, packet, packet_size, 0,
               (struct sockaddr *)&dest_ip, sizeof(dest_ip)) < 0) {
        perror("Failed to send packet");
    } else {
        printf("Packet sent successfully!\n");
    }

    // --- Clean Up ---
    close(sock);
    free(packet);

    return 0;
}

int main(){
    char message[] = "Hello to SAM!\n";
    char source_ip[] = "192.168.1.170";
    char dest_ip[] = "192.168.1.170";
    uint8_t * outbound_packet = byte_packed_packet(dest_ip, source_ip, message);
    uint16_t packet_size = (outbound_packet[2] << 8) | outbound_packet[3];
    int sent = send_network_level_packet(outbound_packet, (int) packet_size,  dest_ip);
}
