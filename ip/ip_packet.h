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

// Packet Builder
typedef struct {
    uint8_t version;
    uint8_t ihl;
    uint16_t tos;
    uint16_t identification;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint32_t * ip_options;
    int ip_options_length;
    char *payload;
   
} PacketStruct;

void base_packet_builder(PacketStruct * packet_struct, const char * dest_ip_string, const char * source_ip_string);

IPPacket * pack_packet(PacketStruct * packet_struct);
void packet_free(IPPacket * packet);
void packet_print_debug(const IPPacket * packet);
