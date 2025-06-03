Need to run as root (because of `SOCKET_RAW`)

To compile and run server (recieves and reads packets)
```
gcc ip_raw_server.c ip_packet.c -o server.out
sudo ./server.out
```


To compile client: 
```
gcc -g ip_datagram_header.c client.c -o client.out
sudo ./client.out
```
