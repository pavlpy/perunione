#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "proto_logic.h"
#include "ext_intr.h"
#define PACKET_BUF_SIZE 128
#define BUF_MASK (PACKET_BUF_SIZE - 1)

/* Transport-facing: pull next outgoing packet from the ring buffer */
bool last_tosend_pack(perunione_context *ctx, Packet *out_pack) {
    if (ctx->tosend_count == 0)
        return false;

    memcpy(out_pack, &(ctx->tosend[ctx->tosend_head]), sizeof(Packet));
    memset(&(ctx->tosend[ctx->tosend_head]), 0, sizeof(Packet));

    ctx->tosend_head = (ctx->tosend_head + 1) & BUF_MASK;
    ctx->tosend_count--;

    return true;
}

/* Transport-facing: push an incoming packet into the ring buffer */
void recieve_pack(perunione_context *ctx, const Packet *pack) {
    if (ctx->getted_count >= PACKET_BUF_SIZE)
        return;

    memcpy(&(ctx->getted[ctx->getted_tail]), pack, sizeof(Packet));
    ctx->getted_tail = (ctx->getted_tail + 1) & BUF_MASK;
    ctx->getted_count++;
}

/* Protocol internal: enqueue a packet for sending */
void __send_pack(perunione_context *ctx, const Packet *pack) {
    if (ctx->tosend_count >= PACKET_BUF_SIZE)
        return;

    memcpy(&(ctx->tosend[ctx->tosend_tail]), pack, sizeof(Packet));
    ctx->tosend_tail = (ctx->tosend_tail + 1) & BUF_MASK;
    ctx->tosend_count++;
}

/* Protocol internal: dequeue a received packet */
bool __last_getted_pack(perunione_context *ctx, Packet *out_pack) {
    if (ctx->getted_count == 0)
        return false;

    memcpy(out_pack, &(ctx->getted[ctx->getted_head]), sizeof(Packet));
    memset(&(ctx->getted[ctx->getted_head]), 0, sizeof(Packet));

    ctx->getted_head = (ctx->getted_head + 1) & BUF_MASK;
    ctx->getted_count--;

    return true;
}
