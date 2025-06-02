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

#define EXPERIMENTAL_PROTOCOL 253

uint16_t calc_checksum(uint16_t * header, int nbytes){
    long sum = 0;
    while(nbytes > 1){
        sum += *header++;
        nbytes -= 2;
    }
    assert(nbytes != 1);
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}
         
unsigned char _is_valid_ip_string(char * ip_string){
    // Implemetation of inet_pton
    const char *regex_pattern = "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$";
    regex_t regex;
    int reti = regcomp(&regex, regex_pattern, REG_EXTENDED);
    if(reti){
        printf("Failed to parse ip address regex\n");
        return reti;
    }
    reti = regexec(&regex, ip_string, 0, NULL, 0);
    if(reti == REG_NOMATCH){
        printf("IP Address %s could not be parsed", ip_string);
        return -1;
    }
    regfree(&regex);
    return 0;
    
}

uint32_t human_readable_to_bits(char * ip_string_literal){
    // Essentially does the same thing as inet_pton
    if (_is_valid_ip_string(ip_string_literal)){
        return 0;
    }
    uint32_t address = 0;
    char * ip_string = (char *) malloc(strlen(ip_string_literal));
    // Copy the string in case this was a hard coded const char *
    strcpy(ip_string, ip_string_literal); 
    char * token = strtok(ip_string, ".");
    int i = 0;
    while(token && i < 4){
        address = address | (atoi(token) << (i*8)); 
        ++i;
        token = strtok(NULL, ".");
    }
    return htonl(address);
}

uint8_t * byte_packed_packet(char * dest_ip_string, char * source_ip_string, char * body){
    // Use uint8_t array to avoid "byte packing"
    // For integers bigger than 8 bytes, use host to network short/long (to ensure big endianness)
    uint8_t version = 4;
    uint8_t ihl = 5;
    uint16_t type_of_service = 0; // best effort
    uint16_t identification = rand() % 65536;
    uint16_t fragmentation_flags_offset = 0; // No fragmentation, no offset
    uint16_t ttl = 64;
    uint16_t protocol = EXPERIMENTAL_PROTOCOL; // Experimental protocol
    uint32_t source_ip = human_readable_to_bits(source_ip_string);
    assert(source_ip != 0);
    uint32_t dest_ip = human_readable_to_bits(dest_ip_string);
    assert(source_ip != 0);

    int ip_header_size = ihl * 4;
    int payload_size = strlen(body);
    int total_packet_length = ip_header_size + payload_size;

    uint8_t * packet = (uint8_t *)malloc(total_packet_length);
    memset(packet, 0, total_packet_length);
    packet[0] = (version << 4) | ihl;
    packet[1] = type_of_service;
    uint16_t net_total_length = htons(net_total_length);
    memcpy(&packet[2], &net_total_length, sizeof(uint16_t));

    uint16_t net_id = htons(identification);
    memcpy(&packet[4], &net_id, sizeof(uint16_t));

    uint16_t net_frag_offset = htons(fragmentation_flags_offset);
    memcpy(&packet[6], &net_frag_offset, sizeof(uint16_t));

    packet[9] = protocol;
    packet[10] = 0;
    packet[11] = 0;

    memcpy(&packet[12], &source_ip, sizeof(uint32_t));
    memcpy(&packet[16], &dest_ip, sizeof(uint32_t));

    unsigned short final_checksum = calc_checksum((unsigned short *) packet, ip_header_size);
    memcpy(&packet[10], &final_checksum, sizeof(uint16_t));

    memcpy(packet+ip_header_size, body, payload_size);


    // Debugging information
    printf("Generated IP Packet:\n");
    printf("  Version: %u, IHL: %u (Header Size: %d bytes)\n", version, ihl, ip_header_size);
    printf("  Total Length: %u bytes\n", total_packet_length);
    printf("  Source IP: %s, Destination IP: %s\n", source_ip_string, dest_ip_string);
    printf("  Protocol: %u\n", protocol);
    printf("  Calculated Checksum: 0x%04x\n", final_checksum);

    printf("Hex dump of the first %d bytes (IP Header):\n", ip_header_size);
    for (int i = 0; i < ip_header_size; i++) {
        printf("%02X ", packet[i]);
        if ((i + 1) % 4 == 0) printf(" "); // Group by 4 bytes
        if ((i + 1) % 16 == 0) printf("\n"); // Newline every 16 bytes
    }
    printf("\n");
    return packet;
}


// TODO: Test and fix send_network_level_packet
/*int send_network_level_packet(uint8_t * packet, int packet_size, char * dest_ip_string){*/
/*    int dest_ip = human_readable_to_bits(dest_ip_string);*/
/*    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);*/
/*    if (sock < 0) {printf("ERROR CREATING SOCKET\n"); return -1;}*/
/*    int optval = 1;*/
/*    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0){*/
/*        printf("FAILED TO SET IP Header included option\n");*/
/*        return -2;*/
/*    }*/
/*    struct sockaddr_in dest_address;*/
/*    dest_address.sin_family = AF_INET;*/
/*    dest_address.sin_port = 0; // not used*/
/*    dest_address.sin_addr.s_addr = dest_ip;*/
/**/
/*    printf("  Protocol: %u (Custom)\n", 253);*/
/**/
/*    // --- Send the Packet ---*/
/*    if (sendto(sock, packet, packet_size, 0,*/
/*               (struct sockaddr *)&dest_ip, sizeof(dest_ip)) < 0) {*/
/*        perror("Failed to send packet");*/
/*    } else {*/
/*        printf("Packet sent successfully!\n");*/
/*    }*/
/**/
/*    // --- Clean Up ---*/
/*    close(sock);*/
/*    free(packet);*/
/**/
/*    return 0;*/
/*}*/

int main(){
    // test human_readable_to_bits
    /*char ip_addr[] = "255.0.0.1";*/
    /*unsigned int bits = human_readable_to_bits(ip_addr);*/
    /*for(int i = 0; i < 4; ++i){*/
    /*    printf("IP ADDRESS: %u\n", (bits & (0xFF << i*8)) >> (i*8));*/
    /*}*/
    char message[] = "Hello to SAM!\n";
    char source_ip[] = "192.168.1.170";
    char dest_ip[] = "192.168.1.170";
    uint8_t * outbound_packet = byte_packed_packet(dest_ip, source_ip, message);
    uint16_t packet_size = (outbound_packet[2] << 8) | outbound_packet[3];
    /*int sent = send_network_level_packet(outbound_packet, (int) packet_size,  dest_ip);*/
    
}
