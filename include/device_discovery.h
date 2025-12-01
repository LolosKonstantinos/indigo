//
// Created by Κωνσταντίνος on 4/16/2025.
//
//todo-> define the error codes after the system is completed
#ifndef INDIGO_DEVICE_DISCOVERY_H
#define INDIGO_DEVICE_DISCOVERY_H


#define ON 1
#define OFF 0


#define DEVICE_TIME_UNTIL_DISCONNECTED 90

//for device discovery
#define PORT 2693
#define MULTICAST_ADDR "239.255.49.152"

//used for discovery packet
#define MAGIC_NUMBER 1841452771

/*1. 4 byte magic number
 *2. 1 byte protocol version (basically the packet version)
 *3. 1 byte message type (what does this received packet mean?)
 *4. 2 bytes payload length in network order
 *5. 56 bytes device hostname (may limit later, for now it's ok)
 */

//message types
#define MSG_INIT_PACKET                 0x01
#define MSG_RESEND                      0x02
#define MSG_SIGNING_REQUEST             0x03
#define MSG_SIGNING_RESPONSE            0x04
#define MSG_FILE_CHUNK                  0x05
#define MSG_STOP_FILE_TRANSMISSION      0x06
#define MSG_PAUSE_FILE_TRANSMISSION     0x07
#define MSG_CONTINUE_FILE_TRANSMISSION  0x08
#define MSG_ERR                         0xff
//more types may be added

#define PAC_VERSION 1

#define DISCOVERY_SEND_PERIOD_SEC 10
#define SIGNATURE_REQUEST_PROCESSING_RATE 1 //1 request per second
#define SIGNATURE_REQUEST_MAX_PER_IP_INTERVAL 6


//for now, it's ok, later we will need to add linux libraries
#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include "Queue.h"
#include "event_flags.h"
#include "mempool.h"

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

typedef struct expected_packet {
    SOCKET socket;
    uint32_t address;
    unsigned char type;
    unsigned char zero[3];
}exp_pack_t;

typedef struct expected_packet_array {
    exp_pack_t *packets;
    uint64_t size;
}exp_pack_array;

//for get_discovery_sockets()
typedef struct SOCKET_LL_NODE {
    struct SOCKET_LL_NODE *next;
    SOCKET sock;
}SOCKET_LL_NODE, SOCKET_NODE;

typedef struct SOCKET_LL {
    SOCKET_NODE *head;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
}SOCKET_LL;

typedef struct IP_SUBNET {
    uint32_t ip;
    uint32_t mask;
    IFTYPE interface_type;
}IP_SUBNET;

//for device discovery system and queue
typedef struct packet_info {
    time_t timestamp;
    struct sockaddr_in address;
    uint8_t mac_address[6];
    uint8_t mac_address_len;
    uint8_t zero;
    SOCKET socket;
    void * packet;
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

#define INDIGO_IP_STATE_DEFAULT 0
#define INDIGO_IP_STATE_SOFT_BANNED 1
#define INDIGO_IP_STATE_HARD_BANNED 2

typedef struct IP_SEND_RATE {
    time_t last_dis_packet;
    time_t last_request;
    time_t ignore_until;
    uint32_t ip;
    uint8_t state;
}IP_SEND_RATE;

typedef struct IP_RATE_ARRAY {
    IP_SEND_RATE *first_ip;
    size_t size;
}IP_RATE_ARRAY;

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

typedef struct INTERFACE_UPDATE_ARGS {
    EFLAG *flag;
    EFLAG *wake;
    HANDLE termination_handle;
    SOCKET_LL *sockets;
    int port;
    uint32_t multicast_addr;
}INTERFACE_UPDATE_ARGS;

typedef struct PACKET_HANDLER_ARGS {
    EFLAG *flag;
    EFLAG *wake;
    QUEUE *queue;
    PACKET_LIST *devices;
    mempool_t *mempool;
}PACKET_HANDLER_ARGS;

typedef struct SIGNING_SERVICE_ARGS {
    EFLAG *flag;
}SIGNING_SERVICE_ARGS;

typedef struct MANAGER_ARGS {
    int port;
    uint32_t multicast_addr;
    EFLAG *flag;
    PACKET_LIST *devices;
}MANAGER_ARGS;


///////////////////////////////////
//                               //
//     GET_DISCOVERY_SOCKETS     //
//                               //
///////////////////////////////////

//the function that creates a linked list of sockets used for the device discovery
SOCKET_NODE *get_discovery_sockets(int port, uint32_t multicast_addr);
//free the sockets linked list
void free_discv_sock_ll(SOCKET_NODE *firstnode);


/////////////////////////////////////////////
///                                       ///
///    get_discovery_sockets() helpers    ///
///                                       ///
/////////////////////////////////////////////

//creates an array of IP_SUBNET
int get_compatible_interfaces(IP_SUBNET **ip_subnet, size_t *count);
//creates a single socket node
SOCKET_NODE *create_discv_sock_node();
//ip and subnet helpers
uint32_t sub_mask_8to32b(uint8_t mask_8b);
uint8_t ips_share_subnet(IP_SUBNET addr1, IP_SUBNET addr2);
uint8_t ip_in_any_subnet(IP_SUBNET addr, const IP_SUBNET *p_addrs, size_t num_addrs);


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

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

/*this thread manages all the application's threads (apart from small worker threads that can be used by any thread),
 *it's responsible for creating the other threads and handling their errors
 *and moving resources between threads*/
int *thread_manager_thread(MANAGER_ARGS *args);

int *send_discovery_thread(SEND_ARGS *args);
int *recv_discovery_thread(RECV_ARGS *args);
int *packet_handler_thread(PACKET_HANDLER_ARGS *args);
int* interface_updater_thread(INTERFACE_UPDATE_ARGS* args);

/*this thread function is called by the packet handler when there is a signing request*/
int *signing_service_thread(SEND_ARGS *args);


///////////////////////////////////////////////////////////////////
///                                                             ///
///                  THREAD_CREATING_FUNCTIONS                  ///
///                                                             ///
///////////////////////////////////////////////////////////////////

int cancel_device_discovery(pthread_t tid, EFLAG *flag);

int create_thread_manager_thread(MANAGER_ARGS **args, int port, uint32_t multicast_address, PACKET_LIST *devices, pthread_t *tid);
int create_discovery_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, SOCKET_LL *sockets, EFLAG *wake_mngr, pthread_t *tid);
int create_receiving_thread(RECV_ARGS **args, SOCKET_LL *sockets, QUEUE *queue, mempool_t* mempool, EFLAG *wake_mngr, pthread_t *tid);
int create_interface_updater_thread(INTERFACE_UPDATE_ARGS **args, int port, uint32_t multicast_address, EFLAG *wake_mngr, SOCKET_LL *sockets, pthread_t *tid);
int create_packet_handler_thread(PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *queue, mempool_t* mempool, PACKET_LIST *dev_list, pthread_t *tid);


/////////////////////////////////////////////////////////////////
///                                                           ///
///                  THREAD_FUNCTION_HELPERS                  ///
///                                                           ///
/////////////////////////////////////////////////////////////////

int create_handle_array_from_recv_info(const RECV_ARRAY *info, HANDLE **handles, size_t *hCount);
void free_recv_array(const RECV_ARRAY *info, mempool_t* mempool);


////////////////////////////////////////////////////////////////////
///                                                              ///
///                  general_use_functions/misc                  ///
///                                                              ///
////////////////////////////////////////////////////////////////////

void print_discovered_device_info(const PACKET_INFO *dev, FILE *stream);


//////////////////////////////////////////////////////////////
///                                                        ///
///                  DEVICE_LL_UTILITIES                   ///
///                                                        ///
//////////////////////////////////////////////////////////////

//they are thread unsafe, first lock the mutex and then use

int remove_device(PACKET_LIST *devices, const PACKET_INFO *dev);
PACKET_NODE *device_exists(const PACKET_LIST *devices, const PACKET_INFO *dev);

/////////////////////////////////////////////////////////////////
///                                                           ///
///                  IP_SEND_RATE_UTILITIES                   ///
///                                                           ///
/////////////////////////////////////////////////////////////////
//todo use a hash table
IP_RATE_ARRAY *ip_rate_array_new();
void ip_rate_array_free(IP_RATE_ARRAY *array);
int ip_rate_add(IP_RATE_ARRAY *buffer,const uint32_t ip);
int ip_rate_get(IP_RATE_ARRAY *restrict const buffer,const size_t index , IP_SEND_RATE **restrict const data);
int ip_rate_set(IP_RATE_ARRAY *restrict buffer,const size_t index ,const IP_SEND_RATE *restrict const data);
int ip_rate_sort(IP_RATE_ARRAY *restrict buffer);
int ip_rate_cmp(const void *s1, const void *s2);
int ip_rate_search(IP_RATE_ARRAY *restrict buffer, const uint32_t ip, size_t *const index);

////////////////////////////////////////////////////////////////////
///                                                              ///
///                  EXPECTED_PACKET_UTILITIES                   ///
///                                                              ///
////////////////////////////////////////////////////////////////////
//todo use hash table

#endif //INDIGO_DEVICE_DISCOVERY_H
