/*
Copyright (c) 2026 Lolos Konstantinos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef NET_IO_H
#define NET_IO_H

#include <Queue.h>
#include <crypto_utils.h>
#include <event_flags.h>
#include <indigo_core/net_monitor.h>
#include <indigo_types.h>
#include <mempool.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_sign.h>

// for now, it's ok, later we will need to add linux libraries
#ifdef _WIN32

#include <iphlpapi.h>
#include <winsock2.h>

#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#endif

#define DEVICE_TIME_UNTIL_DISCONNECTED (90)

// for device discovery
#define PORT (htons(2693))
#define MULTICAST_ADDR ("239.255.49.152")

// used for discovery packet
#define MAGIC_NUMBER_1 (htonl(1841452771))
#define MAGIC_NUMBER_2 (htonl(0x7fffffff))

#ifdef _WIN32
typedef struct RECV_INFO {
    struct sockaddr *source;
    int *fromLen;
    WSABUF *buf;
    OVERLAPPED *overlapped;
    DWORD *flags;
    DWORD *bytes_recv;

    SOCKET socket;
} RECV_INFO;

typedef struct RECV_INFO_ARRAY {
    RECV_INFO *array;
    size_t size;
} RECV_INFO_ARRAY, RECV_ARRAY;

typedef struct SEND_INFO {
    struct sockaddr_in *dest;
    WSABUF *buf;
    OVERLAPPED *overlapped;
    DWORD *bytes;
    SOCKET socket;
} SEND_INFO;
#endif

typedef struct SEND_ARGS {
    int port;
    uint32_t multicast_addr;
    EFLAG *flag;
    EFLAG *wake;
    socket_ll *sockets;
    QUEUE *queue;
    signing_key_pair_t *sign_keys;
} SEND_ARGS;

typedef struct RECV_ARGS {
    QUEUE *queue;
    socket_ll *sockets;
    EFLAG *flag;
    EFLAG *wake;
#ifdef _WIN32
    HANDLE termination_handle;
    HANDLE wake_handle;
#else
    int termination_fd;
    int wake_fd;
#endif
    mempool_t *mempool;
} RECV_ARGS;

//////////////////////////////////////////////////////
///                                                ///
///                  IO_FUNCTIONS                  ///
///                                                ///
//////////////////////////////////////////////////////

// todo check and remove redundant code (there is a comment saying "temporary")
int send_discovery_packets(const int port, const uint32_t multicast_addr, socket_ll *sockets, EFLAG *flag,
                           const uint32_t pCount, const int32_t msec, signing_key_pair_t *sign_key_pair,
                           char username[(MAX_USERNAME_LEN + 1) * sizeof(uint32_t)]);
#ifdef _WIN32
int register_single_receiver(SOCKET sock, RECV_INFO **info, mempool_t *mempool);
int register_multiple_receivers(socket_ll *sockets, RECV_ARRAY *info, mempool_t *mempool, EFLAG *flag);
#else
int register_single_event(int epoll_fd, int fd, struct epoll_event event);
int register_multiple_receivers(int epoll_fd, socket_ll *sockets, size_t *event_count);
#endif
int send_packet(int port, uint32_t addr, socket_ll *sockets, const packet_t *packet, EFLAG *flag);
int send_next_file_packet(active_file_t *file, const unsigned char *pk, socket_ll *sockets, EFLAG *flag);
int send_file_packet(active_file_t *file, uint64_t counter, const unsigned char *pk, socket_ll *sockets, EFLAG *flag);

/////////////////////////////////////////////////////////////
///                                                       ///
///                  IO_HELPER_FUNCTIONS                  ///
///                                                       ///
/////////////////////////////////////////////////////////////

void build_packet(packet_t *restrict packet, unsigned pac_type, const unsigned char id[crypto_sign_PUBLICKEYBYTES],
                  const unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], const void *restrict data);
#ifdef _WIN32
int create_handle_array_from_send_info(const SEND_INFO *info, size_t infolen, HANDLE **handles, size_t *hCount);
void free_send_info(const SEND_INFO *info);
int allocate_recv_info(RECV_INFO **info, mempool_t *mempool);
int allocate_recv_info_fields(RECV_INFO *info, mempool_t *mempool);
void free_recv_info(const RECV_INFO *info, mempool_t *mempool);
#endif

/////////////////////////////////////////////////////////////////
///                                                           ///
///                  THREAD_FUNCTION_HELPERS                  ///
///                                                           ///
/////////////////////////////////////////////////////////////////
#ifdef _WIN32
int create_handle_array_from_recv_info(const RECV_ARRAY *info, HANDLE **handles, size_t *hCount);
void free_recv_array(const RECV_ARRAY *info, mempool_t *mempool);

#endif
//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int *send_thread(SEND_ARGS *args);
int *recv_thread(RECV_ARGS *args);

#endif // NET_IO_H
