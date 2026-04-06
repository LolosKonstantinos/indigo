//
// Created by Constantin on 26/01/2026.
//

#ifndef NET_IO_H
#define NET_IO_H

#include <event_flags.h>
#include <mempool.h>
#include <Queue.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_sign.h>
#include <indigo_types.h>
#include <crypto_utils.h>
#include <indigo_core/net_monitor.h>

//for now, it's ok, later we will need to add linux libraries
#ifdef _WIN32

#include <winsock2.h>
#include <iphlpapi.h>

#endif

#define DEVICE_TIME_UNTIL_DISCONNECTED (90)

//for device discovery
#define PORT (2693)
#define MULTICAST_ADDR ("239.255.49.152")

//used for discovery packet
#define MAGIC_NUMBER_1 (htonl(1841452771))
#define MAGIC_NUMBER_2 (htonl(0x7fffffff))


typedef struct RECV_INFO {
    struct sockaddr *source;
    int *fromLen;
    WSABUF *buf;
    OVERLAPPED *overlapped;
    DWORD *flags;
    DWORD *bytes_recv;

    SOCKET socket;
}RECV_INFO;

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



typedef struct SEND_ARGS {
    int port;
    uint32_t multicast_addr;
    EFLAG *flag;
    EFLAG *wake;
    socket_ll *sockets;
    QUEUE *queue;
    signing_key_pair_t * sign_keys;
    //todo: add username field, must be a thread safe buffer
}SEND_ARGS;

typedef struct RECV_ARGS {
    QUEUE *queue;
    socket_ll *sockets;
    EFLAG *flag;
    EFLAG *wake;
    HANDLE termination_handle;
    HANDLE wake_handle;
    mempool_t *mempool;
}RECV_ARGS;

//////////////////////////////////////////////////////
///                                                ///
///                  IO_FUNCTIONS                  ///
///                                                ///
//////////////////////////////////////////////////////

//todo check and remove redundant code (there is a comment saying "temporary")
int send_discovery_packets(
    int port,
    uint32_t multicast_addr,
    socket_ll *sockets,
    EFLAG *flag,
    uint32_t pCount,
    int32_t msec,
    signing_key_pair_t * sign_key_pair,
    wchar_t username[MAX_USERNAME_LEN]);
int register_single_receiver(SOCKET sock, RECV_INFO **info, mempool_t* mempool);
int register_multiple_receivers(socket_ll *sockets, RECV_ARRAY *info, mempool_t* mempool, EFLAG *flag);

int send_packet(int port, uint32_t addr, socket_ll* sockets, const packet_t* packet, EFLAG *flag);
int send_file_packet(active_file_t *file, const unsigned char *pk, socket_ll* sockets, EFLAG *flag);

/////////////////////////////////////////////////////////////
///                                                       ///
///                  IO_HELPER_FUNCTIONS                  ///
///                                                       ///
/////////////////////////////////////////////////////////////

void build_packet(packet_t * restrict packet, unsigned pac_type, const unsigned char id[crypto_sign_PUBLICKEYBYTES],
                  const unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], const void * restrict data);
int create_handle_array_from_send_info(const SEND_INFO *info, size_t infolen, HANDLE **handles, size_t *hCount);
void free_send_info(const SEND_INFO *info);
int allocate_recv_info(RECV_INFO **info, mempool_t* mempool);
int allocate_recv_info_fields(RECV_INFO *info, mempool_t* mempool);
void free_recv_info(const RECV_INFO *info, mempool_t* mempool);

/////////////////////////////////////////////////////////////////
///                                                           ///
///                  THREAD_FUNCTION_HELPERS                  ///
///                                                           ///
/////////////////////////////////////////////////////////////////

int create_handle_array_from_recv_info(const RECV_ARRAY *info, HANDLE **handles, size_t *hCount);
void free_recv_array(const RECV_ARRAY *info, mempool_t* mempool);

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int *send_thread(SEND_ARGS *args);
int *recv_thread(RECV_ARGS *args);


#endif //NET_IO_H
