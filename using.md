## 📖 API Usage & Integration Guide

`perunione` exports **10 core functions** for complete network and cryptographic control:

```c
PERUN_API void proto_init            (perunione_context *ctx);
PERUN_API void proto_start_handshake (perunione_context *ctx);
PERUN_API void proto_send_disconnect (perunione_context *ctx);
PERUN_API void proto_reset           (perunione_context *ctx);
PERUN_API void proto_send_data       (perunione_context *ctx, const char *data, int len);
PERUN_API void proto_update          (perunione_context *ctx);
PERUN_API void proto_turn_logs_on    (const char *filepath);
PERUN_API void proto_turn_logs_off   (void);
PERUN_API bool last_tosend_pack      (perunione_context *ctx, Packet *out_pack);
PERUN_API void recieve_pack          (perunione_context *ctx, const Packet *pack);
```

### 🧠 Understanding the Context

To utilize this library, you must understand `perunione_context`. This structure encapsulates the entire state of a single cryptographic session. Think of it as `self` in Python or `this` in C++. 

Because of this stateless API design, a single thread or core can handle thousands of concurrent secure connections simply by managing an array of contexts.

```c
typedef struct contx {
    SessionStatus session_status;
    uint16_t      tx_counter;
    uint32_t      last_sended_pack_id;
    uint32_t      last_getted_pack_id;

    BigInt my_private_key;
    BigInt current_shared_secret;

    char*    pending_data;
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

    /* Callback: called automatically with decrypted payload */
    void (*payload_handler)(const char *data, int len);
} perunione_context;
```

The Packet struct is just a 1 KB of data.
```C
typedef struct pack {
    char cont[1024];
} Packet;
```

### 🚀 Quick Start

When you want to spin up the protocol and you don't have an active session, simply initialize this structure with zeros, and then assign your custom decryption callback function to the `payload_handler` field:

```c
void MyPerfectCallbackHandler(const char* data, int len){
    // Your code to handle decrypted incoming data goes here
}
int main(){
    perunione_context my_peer_ctx;
    // Zero out the context 
    memset(&my_peer_ctx, 0, sizeof(perunione_context));

    // Register your high-level message worker callback
    my_peer_ctx.payload_handler = &MyPerfectCallbackHandler;

    // Ready to go!
    proto_init(&my_peer_ctx);
}
```
### 📚 Detailed Function Reference

#### ⚙️ Session Life-Cycle
*   **`void proto_init(perunione_context *ctx);`**
    Prepares the state machine internal contexts and structures. Run this once per session right after zeroing out the context.
*   **`void proto_start_handshake(perunione_context *ctx);`**
    Initiates the 1024-bit ECDH handshake. Generates your secure ephemeral private key, computes the public key coordinates, packs them into an `OP_INIT` packet, and pushes it directly to the outgoing ring buffer.
*   **`void proto_send_disconnect(perunione_context *ctx);`**
    Gracefully notifies the peer that you are closing the channel. Packs and queues an `OP_CONEND` frame to clear reassembly buffers on the other end.
*   **`void proto_reset(perunione_context *ctx);`**
    Instantly wipes all keys, active long-data reassembly chains, and state flags back to `STATUS_DISCONNECTED` without sending wire packets.

#### 🧳 Data Processing & State Machine
*   **`void proto_send_data(perunione_context *ctx, const char *data, int len);`**
    The main transmission pipe. Automatically checks the `tx_counter` threshold (200 packets). If the safety limits are met, it copies the payload safely into an internal buffer (`Use-After-Free` protection) and runs a renegotiation handshake before chunking the file. Otherwise, encrypts data with 7 rounds of custom cascaded quad-AES and feeds it to the queue.
*   **`void proto_update(perunione_context *ctx);`**
    The core protocol engine tick. Processes incoming data packets from the buffer, runs handshakes, decrypts payload streams, handles long-data fragment assembly, and safely invokes your `payload_handler` callback upon complete message assembly.

#### 🪵 Telemetry & Logging
*   **`void proto_turn_logs_on(const char *filepath);`**
    Enables internal telemetry. All handshake details, state anomalies, and cryptographic checkpoints will be safely audited to the specified system file.
*   **`void proto_turn_logs_off(void);`**
    Shuts down the logging subsystem and flushes the open audit descriptors.

#### 🚚 Wire I/O Transport Interface
*   **`bool last_tosend_pack(perunione_context *ctx, Packet *out_pack);`**
    Polled by your network transport loop (e.g., non-blocking UDP `select`). If true, it extracts the oldest encrypted wire-ready frame from the context outgoing queue into `out_pack` (`& BUF_MASK` speed).
*   **`void recieve_pack(perunione_context *ctx, const Packet *pack);`**
    Injected by your network transport loop whenever a raw UDP frame arrives. Pushes the incoming wire packet directly into the context queue for processing on the next `proto_update` tick.


### 💻 Practical Code Snippets

Here is how you actually choreograph these functions inside your application loop.

#### 1. Session Lifecycle & Handshake
To initiate a secure connection with a remote peer:

```c
perunione_context ctx;
memset(&ctx, 0, sizeof(perunione_context));
ctx.payload_handler = &MyPerfectCallbackHandler;

proto_init(&ctx);

// Trigger the 1024-bit ECDH key exchange
proto_start_handshake(&ctx);
```

#### 2. Integrating with a Network Loop (UDP Transport)
This is how you bridge the library's internal ring buffers with your non-blocking system sockets (run this inside your main server tick):

```c
void network_flush_tick(perunione_context *ctx, int socket_fd, struct sockaddr_in *peer_addr) {
    Packet packet;

    // A. TRANSMIT: Extract encrypted wire-ready frames and push them to the socket
    while (last_tosend_pack(ctx, &packet)) {
        sendto(socket_fd, packet.cont, sizeof(packet.cont), 0,
               (struct sockaddr *)peer_addr, sizeof(*peer_addr));
    }

    // B. RECEIVE: Inject raw frames coming from the socket directly into the library
    while (recvfrom(socket_fd, packet.cont, sizeof(packet.cont), 0, NULL, NULL) > 0) {
        recieve_pack(ctx, &packet);
    }

    // C. PROCESS: Let the state machine decrypt data, run handshakes, and route payloads
    proto_update(ctx);
}
```

#### 3. Data Transmission with Auto-Rotation
Sending raw data layer completely abstracting the underlying Perfect Forward Secrecy:

```c
void send_secure_message(perunione_context *ctx, const char *msg) {
    int msg_len = strlen(msg) + 1; // include null terminator
    
    // Automatically handles packet chunking and un-noticable key rotations
    proto_send_data(ctx, msg, msg_len);
}
```

#### 4. Diagnostic Telemetry Logging
Enable this at the boot level to audit your bare-metal cryptographic status:

```c
void app_init(perunione_context *ctx) {
    // Open system file descriptor for real-time security telemetry
    proto_turn_logs_on("/var/log/perunione_audit.log");
    
    // ... setup context and run proto_init ...
}

void app_shutdown(perunione_context *ctx) {
    proto_send_disconnect(ctx); // Gracefully close session
    proto_turn_logs_off();      // Safely flush and close log files
}
```

### Context Safety (Protect the Brain!)
The `perunione_context` structure contains the highly sensitive session keys (`my_private_key` and `current_shared_secret`). 
* **Keep it private**: Never leak the context memory into unsafe log dumps, core dumps, or shared public memory spaces. If the context is compromised, the entire session security is broken.
* **Do not modify internal fields**: Treat the context fields as read-only. **The only field you should safely touch manually is the `payload_handler` callback descriptor.** Manually changing indexes (`tosend_head`, `tx_counter`, etc.) will instantly break the protocol state machine synchronization and result in connection failure or unrecoverable session deadlocks.