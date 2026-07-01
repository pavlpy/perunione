#include "decoencoder.h"
#include "ellyptic.h"
#include "ext_intr.h"
#include "proto_logic.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *proto_log_file = NULL;

#define PROTO_LOG(fmt, ...) do { \
    if (proto_log_file) { \
        fprintf(proto_log_file, fmt "\n", ##__VA_ARGS__); \
        fflush(proto_log_file); \
    } \
} while (0)

void proto_turn_logs_on(const char *filepath) {
    if (proto_log_file) fclose(proto_log_file);
    proto_log_file = fopen(filepath, "a");
}

void proto_turn_logs_off(void) {
    if (proto_log_file) {
        fclose(proto_log_file);
        proto_log_file = NULL;
    }
}

/* Wire format: header + payload, packed */
typedef struct __attribute__((packed)) {
    char     op_code;
    uint64_t data_len;
    uint32_t pack_id;
    char     padding[11];
    char     payload[1000];
} Packet_mask;

/* Append a reassembly node to the long-data chain */
data_container *alloc_container(perunione_context *ctx) {
    data_container *nc = malloc(sizeof(data_container));
    memset(nc, 0, sizeof(data_container));
    ctx->next_cont->next = (char *)nc;
    ctx->container_count++;
    data_container *to_return = ctx->next_cont;
    ctx->next_cont = nc;
    return to_return;
}

void proto_init(perunione_context *ctx) {
    init_dectbl();
    ctx->first_cont = malloc(sizeof(data_container));
    memset(ctx->first_cont, 0, sizeof(data_container));
    ctx->next_cont = malloc(sizeof(data_container));
    memset(ctx->next_cont, 0, sizeof(data_container));
    ctx->first_cont->next = (char *)ctx->next_cont;
}

/* Initiate key exchange: generate keypair, send OP_INIT, enter WAITING_KEY */
void proto_start_handshake(perunione_context *ctx) {
    PROTO_LOG("[ПРОТОКОЛ] Запущено рукопожатие");
    ctx->last_getted_pack_id = 0;
    ctx->last_sended_pack_id = 0;
    Packet pack = {0};
    Packet_mask *packmask = (Packet_mask *)&pack;
    packmask->op_code = OP_INIT;
    packmask->pack_id = ctx->last_sended_pack_id;
    ctx->my_private_key = generate_secure_random_1024();
    PROTO_LOG("[ПРОТОКОЛ] Приватный ключ сгенерирован!");
    ECPoint my_public;
    ecdh_generate_public(&my_public, &ctx->my_private_key);
    PROTO_LOG("[ПРОТОКОЛ] Публичный ключ сгенерирован!");
    memcpy(packmask->payload, &my_public, sizeof(ECPoint));
    ctx->session_status = STATUS_WAITING_KEY;
    ctx->tx_counter = 0;
    __send_pack(ctx, &pack);
}

/* Encrypt and queue user data for sending */
void proto_send_data(perunione_context *ctx, const char *data, const int len) {
    if (ctx->session_status != STATUS_CONNECTED)
        return;

    if (len <= 1000) {
        /* Fits in one packet */
        if (ctx->tx_counter + 1 >= KEY_REFRESH_RATE) {
            proto_send_disconnect(ctx);
            proto_start_handshake(ctx);
            ctx->pending_data = malloc(len);
            memcpy(ctx->pending_data, data, len);
            ctx->pending_data_len = len;
            return;
        }
        Packet pack = {0};
        Packet_mask *packmask = (Packet_mask *)&pack;
        packmask->op_code = OP_SHORT_DATA;
        packmask->data_len = len;
        packmask->pack_id = ctx->last_sended_pack_id + PACK_ID_DELTA;
        ctx->last_sended_pack_id += PACK_ID_DELTA;
        memcpy(packmask->payload, data, len);
        enc(&ctx->current_shared_secret, (char *)&packmask->data_len, DATA_LEN);
        __send_pack(ctx, &pack);
        ctx->tx_counter++;
    }

    if (len > 1000) {
        /* Split across multiple packets */
        uint64_t amount = (len + 999) / 1000;
        if (ctx->tx_counter + amount >= KEY_REFRESH_RATE && ctx->tx_counter != 0) {
            proto_send_disconnect(ctx);
            proto_start_handshake(ctx);
            ctx->pending_data = malloc(len);
            memcpy(ctx->pending_data, data, len);
            ctx->pending_data_len = len;
            return;
        }
        Packet *pkgs = malloc(amount * sizeof(Packet));
        int full_data_len = len;
        for (uint64_t i = 0; i < amount; i++) {
            int copylen = full_data_len >= 1000 ? 1000 : full_data_len;
            Packet *curr = pkgs + i;
            memset(curr, 0, sizeof(Packet));
            Packet_mask *packmask = (Packet_mask *)curr;
            packmask->op_code = (i != amount - 1) ? OP_LONG_DATA : OP_LAST_DATA;
            packmask->data_len = copylen;
            packmask->pack_id = ctx->last_sended_pack_id + PACK_ID_DELTA;
            ctx->last_sended_pack_id += PACK_ID_DELTA;
            memcpy(packmask->payload, data + (i * 1000), copylen);
            enc(&ctx->current_shared_secret, curr->cont + 1, DATA_LEN);
            full_data_len -= 1000;
        }
        for (uint64_t i = 0; i < amount; i++) {
            __send_pack(ctx, pkgs + i);
            ctx->tx_counter++;
        }
        free(pkgs);
    }
}

void proto_send_disconnect(perunione_context *ctx) {
    Packet_mask pack = {0};
    pack.op_code = OP_CONEND;
    pack.pack_id = ctx->last_sended_pack_id + PACK_ID_DELTA;
    ctx->last_sended_pack_id += PACK_ID_DELTA;
    __send_pack(ctx, (Packet *)&pack);
}

/* Free and reinitialize the reassembly chain */
static void reset_containers(perunione_context *ctx) {
    data_container *cc = ctx->first_cont;
    while (cc) {
        data_container *next = (data_container *)cc->next;
        free(cc);
        cc = next;
    }
    ctx->first_cont = malloc(sizeof(data_container));
    memset(ctx->first_cont, 0, sizeof(data_container));
    ctx->next_cont = malloc(sizeof(data_container));
    memset(ctx->next_cont, 0, sizeof(data_container));
    ctx->first_cont->next = (char *)ctx->next_cont;
    ctx->container_count = 2;
}

void proto_reset(perunione_context *ctx) {
    ctx->session_status = STATUS_DISCONNECTED;
    ctx->last_getted_pack_id = 0;
    ctx->last_sended_pack_id = 0;
    ctx->tx_counter = 0;
    reset_containers(ctx);
}

/* Send an OP_ERR to signal protocol violation */
inline static void send_conerr(perunione_context *ctx) {
    Packet_mask pack = {0};
    pack.op_code = OP_ERR;
    pack.pack_id = ctx->last_sended_pack_id + PACK_ID_DELTA;
    ctx->last_sended_pack_id += PACK_ID_DELTA;
    __send_pack(ctx, (Packet *)&pack);
}

/* Reject duplicate or out-of-order packet IDs */
static bool check_pack_id(perunione_context *ctx, uint32_t id) {
    if (id != ctx->last_getted_pack_id + PACK_ID_DELTA) {
        PROTO_LOG("[ПРОТОКОЛ] Неверный ID пакета: ожидалось %d, получен %i",
               ctx->last_getted_pack_id + PACK_ID_DELTA, id);
        send_conerr(ctx);
        return false;
    }
    ctx->last_getted_pack_id = id;
    return true;
}

/* Process one incoming packet from the ring buffer */
void proto_update(perunione_context *ctx) {
    Packet pack;
    if (!__last_getted_pack(ctx, &pack))
        return;

    Packet_mask *packmask = (Packet_mask *)&pack;
    uint8_t op = packmask->op_code;

    switch (op) {
    case OP_INIT: {
        ECPoint their_public;
        ctx->last_getted_pack_id = packmask->pack_id;
        memcpy(&their_public, packmask->payload, sizeof(ECPoint));
        if (!is_valid_public_key(&their_public)) {
            ctx->session_status = STATUS_DISCONNECTED;
            send_conerr(ctx);
            return;
        }
        /* If we already sent our INIT, this is the peer's reply */
        if (ctx->session_status != STATUS_WAITING_KEY) {
            ctx->my_private_key = generate_secure_random_1024();
            ECPoint my_public;
            ecdh_generate_public(&my_public, &ctx->my_private_key);
            Packet_mask response = {0};
            response.op_code = OP_INIT;
            response.pack_id = ctx->last_sended_pack_id;
            memcpy(response.payload, &my_public, sizeof(ECPoint));
            __send_pack(ctx, (Packet *)&response);
        }
        ecdh_compute_shared_secret(&ctx->current_shared_secret,
                                   &their_public, &ctx->my_private_key);
        ctx->session_status = STATUS_CONNECTED;
        ctx->tx_counter = 0;

        /* Flush any data queued before the handshake completed */
        if (ctx->pending_data_len > 0 && ctx->pending_data != NULL) {
            char *data_to_free = ctx->pending_data;
            proto_send_data(ctx, ctx->pending_data, ctx->pending_data_len);
            free(data_to_free);
            ctx->pending_data = NULL;
            ctx->pending_data_len = 0;
        }
        break;
    }

    case OP_SHORT_DATA: {
        if (ctx->session_status != STATUS_CONNECTED) {
            PROTO_LOG("[LOG_LOGIC] Ошибка: Невозможно обработать пакет: соединение не установлено");
            send_conerr(ctx);
            return;
        }
        dec(&ctx->current_shared_secret, (char *)&packmask->data_len, DATA_LEN);
        int len = packmask->data_len;
        if (check_pack_id(ctx, packmask->pack_id))
            ctx->payload_handler(packmask->payload, len);
        break;
    }

    case OP_LONG_DATA: {
        if (ctx->session_status == STATUS_CONNECTED) {
            dec(&ctx->current_shared_secret, (char *)&packmask->data_len, DATA_LEN);
            if (check_pack_id(ctx, packmask->pack_id)) {
                data_container *container = alloc_container(ctx);
                memcpy(container->curr, packmask->payload, packmask->data_len);
            }
        }
        break;
    }

    case OP_LAST_DATA: {
        if (ctx->session_status == STATUS_CONNECTED) {
            dec(&ctx->current_shared_secret, (char *)&packmask->data_len, DATA_LEN);
            if (check_pack_id(ctx, packmask->pack_id)) {
                data_container *container = alloc_container(ctx);
                memcpy(container->curr, packmask->payload, packmask->data_len);

                /* Assemble all fragments into a contiguous buffer */
                uint64_t num_data = ctx->container_count - 2;
                uint64_t result_len = (num_data - 1) * 1000 + packmask->data_len;
                char *result = malloc(result_len);
                data_container *cc = (data_container *)ctx->first_cont->next;
                for (uint32_t ci = 0; ci < num_data; ci++) {
                    memcpy(result + ci * 1000, cc->curr,
                           ci == num_data - 1 ? packmask->data_len : 1000);
                    data_container *last_ptr = cc;
                    cc = (data_container *)cc->next;
                    free(last_ptr);
                }
                ctx->payload_handler(result, result_len);
                free(result);
                reset_containers(ctx);
            }
        }
        break;
    }

    case OP_CONEND:
        PROTO_LOG("[ПРОТОКОЛ] Пир отключился");
        reset_containers(ctx);
        ctx->session_status = STATUS_DISCONNECTED;
        break;
    }
}
