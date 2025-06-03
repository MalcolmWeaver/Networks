#include <stdint.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "ip_packet.h"

int validate_ip_string(const char *ip_string) {
    const char *regex_pattern = "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$";
    regex_t regex;
    int reti = regcomp(&regex, regex_pattern, REG_EXTENDED);
    if (reti) return -3;
    reti = regexec(&regex, ip_string, 0, NULL, 0);
    regfree(&regex);
    return reti == REG_NOMATCH ? INVALID_IP : SUCCESS;
}

uint32_t ip_string_to_address(const char *ip_string) {
    int err = validate_ip_string(ip_string);
    if (err != 0) return err;

    char *temp = strdup(ip_string);
    if (!temp) return MEMORY_ERROR;

    uint32_t address = 0;
    char *token = strtok(temp, ".");
    for (int i = 0; token && i < 4; i++) {
        address |= (atoi(token) << ((3-i) * 8));
        token = strtok(NULL, ".");
    }
    free(temp);
    return htonl(address);
}

uint16_t calc_checksum(const uint8_t *data, int nbytes) {
    // TODO: FOR LOOP TO EXPLICITLY IGNORE BYTES 11/12 (CHECKSUM)
    long sum = 0;
    const uint16_t *header = (const uint16_t *)data;
    while (nbytes > 1) {
        sum += *header++;
        nbytes -= 2;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}


void packet_free(IPPacket *packet) {
    if(!packet){return;}
    free(packet->data);
    packet->data = NULL;
    packet->total_length = 0;
    packet->header_length = 0;
}

