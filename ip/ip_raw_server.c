// THE PURPOSE OF THIS FILE IS TO RECIEVE AND READ THE
// IP DATAGRAMS SENT FROM .client.c
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include "ip_packet.h"

#define MAX_BUF_SZ 1024

int main(){
    printf("STARTING SERVER...\n\n\n");
    int sockfd = socket(AF_INET, SOCK_RAW, 253);
    uint8_t buffer[MAX_BUF_SZ];
    if (sockfd < 0){perror("FILE ISSUE"); return -1;}
    while (1) {
        ssize_t bytes_received = recv(sockfd, buffer, MAX_BUF_SZ, 0);
        if (bytes_received < 0) {
            perror("recv failed");
            continue;
        } else if (bytes_received == 0) {
            printf("No data received\n");
            continue;
        }
        printf("Received %zd bytes\n", bytes_received);
        IPPacket * packet = unpack_packet(buffer, bytes_received);
        packet_free(packet);
    }
}
