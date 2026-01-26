//
// Created by Constantin on 26/01/2026.
//

#ifndef NET_IO_H
#define NET_IO_H
#include <indigo_core/indigo_core.h>
#include <event_flags.h>
#include <mempool.h>
#include <Queue.h>
//for now, it's ok, later we will need to add linux libraries
#ifdef _WIN32

#include <ws2tcpip.h>
#include <winsock2.h>
#include <iphlpapi.h>

#endif

#define DEVICE_TIME_UNTIL_DISCONNECTED 90

//for device discovery
#define PORT 2693
#define MULTICAST_ADDR "239.255.49.152"

//used for discovery packet
#define MAGIC_NUMBER 1841452771

//message types
#define MSG_INIT_PACKET                 0x01
#define MSG_RESEND                      0x02
#define MSG_SIGNING_REQUEST             0x03
#define MSG_SIGNING_RESPONSE            0x04
#define MSG_FILE_SENDING_REQUEST        0x05
#define MSG_FILE_CHUNK                  0x06
#define MSG_STOP_FILE_TRANSMISSION      0x07
#define MSG_PAUSE_FILE_TRANSMISSION     0x08
#define MSG_CONTINUE_FILE_TRANSMISSION  0x09
#define MSG_ERR                         0xff
//more types may be added

#define PAC_VERSION 1
#define DISCOVERY_SEND_PERIOD_SEC 10

#define PAC_DATA_BYTES (1<<10)
#define PAC_MIN_BYTES 7
#define PAC_MAX_BYTES sizeof(PACKET)
//the packet that is sent for everything, device discovery, signature handshakes, file chunks, etc.
//it's a little big but since the buffer is at the end there is no need to send the whole thing
typedef struct udp_packet{
    uint32_t magic_number;
    unsigned char pac_type;
    unsigned char pac_version;
    int16_t zero;
    char data[PAC_DATA_BYTES];
}PACKET;

typedef struct udp_packet_header {
    uint32_t magic_number;
    unsigned char pac_type;
    unsigned char pac_version;
}PACKET_HEADER;

//for device discovery system and queue
typedef struct packet_info {
    time_t timestamp;
    struct sockaddr_in address;
    uint8_t mac_address[6];
    uint8_t mac_address_len;
    uint8_t zero;
    SOCKET socket;
    void * packet; //may not need it as when we send the received buffer the packet is already in there
}PACKET_INFO;

typedef struct PACKET_INFO_NODE {
    struct PACKET_INFO_NODE *next;
    PACKET_INFO packet;
}PACKET_INFO_NODE, PACKET_NODE;

typedef struct PACKET_INFO_LIST {
    PACKET_NODE *head;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
}PACKET_INFO_LIST, PACKET_LIST;

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
    RECV_INFO *head;
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
    SOCKET_LL *sockets;
}SEND_ARGS;

typedef struct RECV_ARGS {
    QUEUE *queue;
    SOCKET_LL *sockets;
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
int send_discovery_packets(int port, uint32_t multicast_addr, SOCKET_LL *sockets, EFLAG *flag, uint32_t pCount, int32_t msec);
int register_single_receiver(SOCKET sock, RECV_INFO **info, mempool_t* mempool);
int register_multiple_receivers(SOCKET_LL *sockets, RECV_ARRAY *info, mempool_t* mempool, EFLAG *flag);

int send_packet(int port, uint32_t addr, SOCKET socket, PACKET *packet, EFLAG *flag);


/////////////////////////////////////////////////////////////
///                                                       ///
///                  IO_HELPER_FUNCTIONS                  ///
///                                                       ///
/////////////////////////////////////////////////////////////

void build_packet(PACKET * restrict packet, const unsigned pac_type,const void * restrict data);
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
///
int *send_discovery_thread(SEND_ARGS *args);
int *recv_discovery_thread(RECV_ARGS *args);
#endif //NET_IO_H
