#ifndef PROTO_LOGIC_H
#define PROTO_LOGIC_H

#include <stdint.h>
#include "ellyptic.h"

/* Operation codes */
#define OP_INIT        0
#define OP_SHORT_DATA  1
#define OP_LONG_DATA   2
#define OP_LAST_DATA   3
#define OP_CONEND      4
#define OP_ERR         5

/* Encrypted payload length per packet (do not change) */
#define DATA_LEN 1023

/* Packet ID increment between consecutive packets */
#define PACK_ID_DELTA 3

/* Re-key after this many transmitted packets */
#define KEY_REFRESH_RATE 200

#define PERUN_API __attribute__((visibility("default")))

typedef enum {
    STATUS_DISCONNECTED,
    STATUS_WAITING_KEY,
    STATUS_CONNECTED
} SessionStatus;

#include "ext_intr.h"

/* Linked-list node for long-data reassembly */
typedef struct {
    char *next;
    char  curr[1000];
} data_container;

typedef struct contx {
    SessionStatus session_status;
    uint16_t      tx_counter;
    uint32_t      last_sended_pack_id;
    uint32_t      last_getted_pack_id;

    BigInt my_private_key;
    BigInt current_shared_secret;

    char*   pending_data;
    uint64_t pending_data_len;

    /* Outgoing ring buffer */
    Packet  tosend[PACKET_BUF_SIZE];
    uint8_t tosend_head;
    uint8_t tosend_tail;
    uint8_t tosend_count;

    /* Incoming ring buffer */
    Packet  getted[PACKET_BUF_SIZE];
    uint8_t getted_head;
    uint8_t getted_tail;
    uint8_t getted_count;

    /* Long-data reassembly chain */
    data_container *first_cont;
    data_container *next_cont;
    uint64_t        container_count;

    /* Callback: called with decrypted payload */
    void (*payload_handler)(const char *data, int len);
} perunione_context;

PERUN_API void proto_init            (perunione_context *ctx);
PERUN_API void proto_start_handshake (perunione_context *ctx);
PERUN_API void proto_send_disconnect (perunione_context *ctx);
PERUN_API void proto_reset           (perunione_context *ctx);
PERUN_API void proto_send_data       (perunione_context *ctx, const char *data, int len);
PERUN_API void proto_update          (perunione_context *ctx);
PERUN_API void proto_turn_logs_on    (const char *filepath);
PERUN_API void proto_turn_logs_off   (void);

#endif
