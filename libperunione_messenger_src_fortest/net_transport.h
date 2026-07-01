#ifndef NET_TRANSPORT_H
#define NET_TRANSPORT_H

#include <stdint.h>

#define HOST_PORT 37000
#define PEER_PORT 37001
#define PEER_IP   "127.0.0.1"

void net_transport_init(uint16_t host_port, const char *peer_ip, uint16_t peer_port);
void net_transport_tick(void);
int  net_transport_fd(void);
void net_transport_close(void);

#endif
