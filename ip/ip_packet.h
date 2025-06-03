#include <stdint.h>

#define EXPERIMENTAL_PROTOCOL 253
#define IPV4_VERSION 4

typedef enum {
    SUCCESS = 0,
    MEMORY_ERROR = -1,
    INVALID_IP = -5,
    REGEX_ERROR = -6
} ErrorCode;

uint32_t ip_string_to_address(const char * ip_string);

// Packet structure
typedef struct {
    uint8_t *data;
    uint16_t total_length;
    uint16_t header_length;
    uint32_t dest_ip;
    uint32_t source_ip;
} IPPacket;

uint16_t calc_checksum(const uint8_t *data, int nbytes);
void packet_free(IPPacket * packet);
void packet_print_debug(const IPPacket * packet);

