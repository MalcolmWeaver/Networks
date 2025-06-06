
Need to run as root (because of `SOCKET_RAW`)

To compile and run server (recieves and reads packets)
```
gcc ip_packet.c ip_packet_unpacking.c ip_raw_server.c -o server.out
sudo ./server.out
```


To compile client (sends packets to a public IP address or an IP address on your LAN): 
```
gcc -g ip_packet.c ip_packet_builder.c ip_raw_client.c -o client.out
sudo ./client.out
```
