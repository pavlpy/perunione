#include "perunione.h"
#include "net_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#define PAYLOAD_OFFSET 24
#define SELECT_TIMEOUT_MS 100
#define SELECT_TIMEOUT_US (SELECT_TIMEOUT_MS * 1000)

static perunione_context ctx;

static void load_passport_key(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[!] Не удалось открыть %s: ", path);
        perror("");
        fprintf(stderr, "[!] key_encrypt_code будет нулевым (MITM уязвимость)\n");
        return;
    }
    size_t n = fread(ctx.key_encrypt_code, 1, 128, f);
    fclose(f);
    if (n != 128) {
        fprintf(stderr, "[!] Прочитано только %zu байт из %s (ожидалось 128)\n", n, path);
        fprintf(stderr, "[!] key_encrypt_code будет нулевым (MITM уязвимость)\n");
        memset(ctx.key_encrypt_code, 0, 128);
    } else {
        printf("[*] key_encrypt_code загружен из %s\n", path);
    }
}

static void show_ciphertext_preview(void) {
    if (ctx.tosend_count == 0) return;
    uint8_t last = (ctx.tosend_tail - 1) & BUF_MASK;
    char preview[11];
    memcpy(preview, ctx.tosend[last].cont + PAYLOAD_OFFSET, 10);
    preview[10] = '\0';
    printf("[ШИФР] первые 10 символов payload: \"%s\"\n", preview);
}

void on_payload_received(const char *data, int len) {
    char buf[2048];
    int n = len < (int)sizeof(buf) - 1 ? len : (int)sizeof(buf) - 1;
    memcpy(buf, data, n);
    buf[n] = '\0';
    printf("\n[СООБЩЕНИЕ] %s\n> ", buf);
    fflush(stdout);
}

int main(int argc, char **argv) {
    uint16_t host_port = HOST_PORT;
    char     peer_ip[64] = PEER_IP;
    uint16_t peer_port = PEER_PORT;

    if (argc >= 3) {
        host_port = (uint16_t)atoi(argv[1]);
        char *colon = strchr(argv[2], ':');
        if (colon) {
            size_t ip_len = colon - argv[2];
            if (ip_len >= sizeof(peer_ip)) ip_len = sizeof(peer_ip) - 1;
            memcpy(peer_ip, argv[2], ip_len);
            peer_ip[ip_len] = '\0';
            peer_port = (uint16_t)atoi(colon + 1);
        }
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.payload_handler = on_payload_received;

    load_passport_key("passport.key");

    proto_init(&ctx);  // calls init_dectbl() internally
    net_transport_init(host_port, peer_ip, peer_port);

    printf("Пир %s:%d, /connect /restart /quit\n\n", peer_ip, peer_port);

    char input[2048];
    while (1) {
        net_transport_tick(&ctx);
        proto_update(&ctx);

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int sock = net_transport_fd();
        if (sock >= 0) FD_SET(sock, &rfds);
        int maxfd = sock > STDIN_FILENO ? sock : STDIN_FILENO;

        struct timeval tv = {0, SELECT_TIMEOUT_US};
        select(maxfd + 1, &rfds, NULL, NULL, &tv);

        if (!FD_ISSET(STDIN_FILENO, &rfds)) continue;

        if (!fgets(input, sizeof(input), stdin)) break;
        size_t slen = strlen(input);
        if (slen > 0 && input[slen - 1] == '\n') input[--slen] = '\0';
        if (slen == 0) continue;

        if (strcmp(input, "/quit") == 0) break;

        if (strcmp(input, "/connect") == 0) {
            if (ctx.session_status == STATUS_CONNECTED) {
                printf("[*] Уже подключено.\n");
            } else {
                proto_start_handshake(&ctx);
            }
            continue;
        }

        if (strcmp(input, "/restart") == 0) {
            if (ctx.session_status != STATUS_DISCONNECTED) {
                proto_send_disconnect(&ctx);
            }
            proto_reset(&ctx);
            net_transport_tick(&ctx);
            proto_start_handshake(&ctx);
            continue;
        }

        if (input[0] == '/') {
            printf("[*] Неизвестная команда: %s\n", input);
            continue;
        }

        if (ctx.session_status != STATUS_CONNECTED) {
            printf("[*] Нет соединения. Используйте /connect.\n");
            continue;
        }

        proto_send_data(&ctx, input, (int)slen + 1);
        show_ciphertext_preview();
    }

    net_transport_close();
    printf("Выход.\n");
    return 0;
}
