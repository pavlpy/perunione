#include "decoencoder.h"
#include "ellyptic.h"
#include "ext_intr.h"
#include "proto_logic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int test_passed = 0;
static int test_failed = 0;

#define TEST(name) do { printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { printf("OK\n"); test_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); test_failed++; } while(0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAIL(msg); return; } } while(0)

static void test_enc_dec_roundtrip(void) {
    TEST("enc/dec roundtrip");
    init_dectbl();

    BigInt key = {0};
    for (int i = 0; i < 16; i++) key.w[i] = 0xDEADBEEFCAFEBABEULL;

    char original[1024];
    char buffer[1024];
    for (int i = 0; i < 1024; i++) {
        original[i] = (char)(i & 0xFF);
        buffer[i]   = (char)(i & 0xFF);
    }

    enc(&key, buffer, 1024);

    int all_diff = 0;
    for (int i = 0; i < 1024; i++)
        if (buffer[i] != original[i]) all_diff = 1;
    ASSERT(all_diff, "encryption didn't change data");

    dec(&key, buffer, 1024);
    ASSERT(memcmp(original, buffer, 1024) == 0, "decrypted data doesn't match original");

    PASS();
}

static void test_enc_dec_empty(void) {
    TEST("enc/dec zero-length (should not crash)");
    BigInt key = {0};
    char buf[4] = {0};
    enc(&key, buf, 0);
    dec(&key, buf, 0);
    PASS();
}

static void test_ecdh_keygen(void) {
    TEST("ECDH key generation and validation");
    BigInt priv = generate_secure_random_1024();
    ASSERT(!bi_is_zero(&priv), "private key is zero");

    ECPoint pub;
    ecdh_generate_public(&pub, &priv);
    ASSERT(!pub.is_infinity, "public key is infinity");
    ASSERT(is_valid_public_key(&pub), "public key is not on curve");
    PASS();
}

static void test_ecdh_shared_secret(void) {
    TEST("ECDH shared secret agreement");
    BigInt alice_priv = generate_secure_random_1024();
    BigInt bob_priv   = generate_secure_random_1024();

    ECPoint alice_pub, bob_pub;
    ecdh_generate_public(&alice_pub, &alice_priv);
    ecdh_generate_public(&bob_pub,   &bob_priv);

    BigInt alice_shared, bob_shared;
    ecdh_compute_shared_secret(&alice_shared, &bob_pub,   &alice_priv);
    ecdh_compute_shared_secret(&bob_shared,   &alice_pub, &bob_priv);

    ASSERT(memcmp(&alice_shared, &bob_shared, sizeof(BigInt)) == 0,
           "shared secrets don't match");
    PASS();
}

static char last_payload[8192];
static int  last_len = 0;

static void test_payload_handler(const char *data, int len) {
    if (len > (int)sizeof(last_payload)) len = (int)sizeof(last_payload);
    memcpy(last_payload, data, len);
    last_len = len;
}

static void load_passport_key(perunione_context *ctx, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen passport.key");
        return;
    }
    size_t n = fread(ctx->key_encrypt_code, 1, 128, f);
    fclose(f);
    if (n != 128) {
        fprintf(stderr, "Warning: read %zu bytes from %s, expected 128\n", n, path);
    }
}

static void route_packet(perunione_context *from, perunione_context *to) {
    Packet p;
    while (last_tosend_pack(from, &p)) {
        recieve_pack(to, &p);
    }
}

static void test_full_handshake_and_send(void) {
    TEST("full handshake + send/receive cycle");

    init_dectbl();

    perunione_context alice, bob;
    memset(&alice, 0, sizeof(alice));
    memset(&bob,   0, sizeof(bob));

    load_passport_key(&alice, "passport.key");
    load_passport_key(&bob,   "passport.key");
    ASSERT(memcmp(alice.key_encrypt_code, bob.key_encrypt_code, 128) == 0,
           "passport keys don't match");

    alice.payload_handler = test_payload_handler;
    bob.payload_handler   = test_payload_handler;

    proto_init(&alice);
    proto_init(&bob);

    proto_start_handshake(&alice);
    route_packet(&alice, &bob);

    proto_update(&bob);
    route_packet(&bob, &alice);

    proto_update(&alice);

    ASSERT(alice.session_status == STATUS_CONNECTED, "alice not connected");
    ASSERT(bob.session_status   == STATUS_CONNECTED, "bob not connected");

    const char *msg = "Hello from Alice!";
    last_len = 0;
    proto_send_data(&alice, msg, (int)strlen(msg) + 1);
    route_packet(&alice, &bob);

    proto_update(&bob);

    ASSERT(last_len > 0, "bob didn't receive anything");
    ASSERT(strcmp(last_payload, msg) == 0, "bob received wrong message");

    PASS();
}

static void test_long_data(void) {
    TEST("long data (multi-packet) transmission");

    perunione_context alice, bob;
    memset(&alice, 0, sizeof(alice));
    memset(&bob,   0, sizeof(bob));

    load_passport_key(&alice, "passport.key");
    load_passport_key(&bob,   "passport.key");

    alice.payload_handler = test_payload_handler;
    bob.payload_handler   = test_payload_handler;

    proto_init(&alice);
    proto_init(&bob);

    proto_start_handshake(&alice);
    route_packet(&alice, &bob);
    proto_update(&bob);
    route_packet(&bob, &alice);
    proto_update(&alice);

    ASSERT(alice.session_status == STATUS_CONNECTED, "alice not connected");
    ASSERT(bob.session_status   == STATUS_CONNECTED, "bob not connected");

    char long_msg[5000];
    for (int i = 0; i < 4999; i++) long_msg[i] = 'A' + (i % 26);
    long_msg[4999] = '\0';

    last_len = 0;
    proto_send_data(&alice, long_msg, 5000);
    route_packet(&alice, &bob);

    for (int tries = 0; tries < 20 && last_len == 0; tries++)
        proto_update(&bob);

    ASSERT(last_len == 5000, "bob received wrong length");
    ASSERT(memcmp(last_payload, long_msg, 5000) == 0, "bob received wrong long data");

    PASS();
}

static void test_reset(void) {
    TEST("proto_reset clears state");

    perunione_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.payload_handler = test_payload_handler;
    proto_init(&ctx);
    proto_start_handshake(&ctx);
    ctx.session_status = STATUS_CONNECTED;

    proto_reset(&ctx);
    ASSERT(ctx.session_status == STATUS_DISCONNECTED, "status not reset");
    ASSERT(ctx.tx_counter == 0, "tx_counter not reset");

    PASS();
}

static void test_disconnect(void) {
    TEST("disconnect notification");

    perunione_context alice, bob;
    memset(&alice, 0, sizeof(alice));
    memset(&bob,   0, sizeof(bob));

    load_passport_key(&alice, "passport.key");
    load_passport_key(&bob,   "passport.key");

    alice.payload_handler = test_payload_handler;
    bob.payload_handler   = test_payload_handler;

    proto_init(&alice);
    proto_init(&bob);

    proto_start_handshake(&alice);
    route_packet(&alice, &bob);
    proto_update(&bob);
    route_packet(&bob, &alice);
    proto_update(&alice);

    ASSERT(alice.session_status == STATUS_CONNECTED, "alice not connected before disconnect");

    proto_send_disconnect(&alice);
    route_packet(&alice, &bob);
    proto_update(&bob);

    ASSERT(bob.session_status == STATUS_DISCONNECTED, "bob not disconnected after OP_CONEND");

    PASS();
}

int main(void) {
    printf("=== libperunione test suite ===\n\n");

    test_enc_dec_roundtrip();
    test_enc_dec_empty();
    test_ecdh_keygen();
    test_ecdh_shared_secret();
    test_full_handshake_and_send();
    test_long_data();
    test_reset();
    test_disconnect();

    printf("\n=== Results: %d passed, %d failed ===\n", test_passed, test_failed);
    return test_failed > 0 ? 1 : 0;
}
