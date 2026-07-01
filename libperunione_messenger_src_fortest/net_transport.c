#include "ext_intr.h"
#include "net_transport.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int sock_fd = -1;
static struct sockaddr_in peer_addr;

void net_transport_init(uint16_t host_port, const char *peer_ip, uint16_t peer_port) {
    sock_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock_fd < 0) {
        perror("socket");
        return;
    }

    struct sockaddr_in host_addr;
    memset(&host_addr, 0, sizeof(host_addr));
    host_addr.sin_family = AF_INET;
    host_addr.sin_addr.s_addr = INADDR_ANY;
    host_addr.sin_port = htons(host_port);

    if (bind(sock_fd, (struct sockaddr *)&host_addr, sizeof(host_addr)) < 0) {
        perror("bind");
        close(sock_fd);
        sock_fd = -1;
        return;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    if (inet_pton(AF_INET, peer_ip, &peer_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock_fd);
        sock_fd = -1;
        return;
    }

    printf("[ТРАНСПОРТ] UDP сокет запущен на порту %d, пир %s:%d\n",
           host_port, peer_ip, peer_port);
}

void net_transport_tick(void) {
    if (sock_fd < 0) return;

    Packet out;
    while (last_tosend_pack(&out)) {
        ssize_t sent = sendto(sock_fd, out.cont, sizeof(out.cont), 0,
                              (struct sockaddr *)&peer_addr, sizeof(peer_addr));
        if (sent < 0) {
            perror("sendto");
        }
    }

    Packet in;
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t n;
    while ((n = recvfrom(sock_fd, in.cont, sizeof(in.cont), 0,
                         (struct sockaddr *)&from, &from_len)) > 0) {
        recieve_pack(&in);
        from_len = sizeof(from);
    }
}

int net_transport_fd(void) {
    return sock_fd;
}

void net_transport_close(void) {
    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }
}
