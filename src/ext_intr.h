#ifndef EXT_INTR_H
#define EXT_INTR_H

#include <stdint.h>
#include <stdbool.h>

#define PACKET_BUF_SIZE 128
#define BUF_MASK (PACKET_BUF_SIZE - 1)

/* Raw transport packet: 1024-byte opaque blob */
typedef struct pack {
    char cont[1024];
} Packet;

typedef struct contx perunione_context;

#define PERUN_API __attribute__((visibility("default")))

/* Pop one packet from the to-send ring buffer (transport calls this) */
PERUN_API bool  last_tosend_pack   (perunione_context *ctx, Packet *out_pack);

/* Push one received packet into the ring buffer (transport calls this) */
PERUN_API void  recieve_pack       (perunione_context *ctx, const Packet *pack);

/* Push one packet into the to-send ring buffer (protocol internal) */
void            __send_pack        (perunione_context *ctx, const Packet *pack);

/* Pop one packet from the received ring buffer (protocol internal) */
bool            __last_getted_pack (perunione_context *ctx, Packet *out_pack);

#endif
