#include <stdint.h>

#include "ip_packet.h"

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
} PacketBuilder;

// The following allocates memory.
// Caller is responsible for freeing the PacketBuilder
// TODO
PacketBuilder * create_packet(const char * payload, const char * src_ip, const char * dst_ip, void (*packet_builder)(PacketBuilder*, const char *, const char *));

void packet_builder_free(PacketBuilder * packet_builder_ptr);

// The following can be used or extended to implement the 
// strategy pattern for header building with each module 
// (raw, UDP, TCP). Define your own packet_builder, 
// passing a pointer to that function to create_packet.
void base_packet_builder(PacketBuilder * packet_struct, const char * dest_ip_string, const char * source_ip_string);

IPPacket * pack_packet(PacketBuilder * packet_struct);


