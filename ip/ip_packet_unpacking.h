#include <stdint.h>
#include "ip_packet.h"

// The following allocates memory for the IP packet.
// Caller is responsible for freeing.
IPPacket * unpack_packet(uint8_t * byte_buffer, int bytes_recieved);
