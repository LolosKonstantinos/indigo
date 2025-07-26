//
// Created by Κωνσταντίνος on 4/16/2025.
//
//todo-> define the error codes after the system is completed
#ifndef NETWERK_DEVICE_DISCOVERY_H
#define NETWERK_DEVICE_DISCOVERY_H

//for TCP/IP communication (not for device discovery)
#define TCP_PORT 57362

//for device discovery
#define DISCOVERY_PORT 57883
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
#define MSG_INIT_PAC 0x01
#define MSG_INIT_REC 0x02
#define MSG_ERR      0xff
//more types may be added

#define PAC_VERSION 1

//return values and error codes for the device discovery thread system
#define DDTS_BUG 0xff
#define DDTS_UNSUPPORTED 0xfe
#define DDTS_MEMORY_ERROR 0x01
#define DDTS_QUEUE_ERROR 0x02
#define DDTS_WINLIB_ERROR 0x04 //todo check later and report more detailed return code, why the windows function failed
#define DDTS_BAD_REQUEST 0x08
#define DDTS_OVERRIDE_INSTRUCTION 0x10
#define DDTS_SYSTEM_ERROR 0x20 //todo same as winlib_error


//for now, it's ok, later we will need to add linux libraries
#ifdef _WIN32

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include "Queue.h"
#include "dynamic_array.h"
#include <errno.h>


#endif

//the packet that is sent to the multicast group
typedef struct DISCV_PAC{
    uint32_t magic_number;
    unsigned char pac_version;
    unsigned char pac_type;
    uint16_t pac_length;
    char hostname[MAX_HOSTNAME_LEN];
}DISCV_PAC;

//for get_discovery_sockets()
typedef struct SOCKET_LL_NODE {
    SOCKET sock;
    struct SOCKET_LL_NODE *next;
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
typedef struct DISCOVERED_DEVICE {
    char hostname[MAX_HOSTNAME_LEN];
    time_t timestamp;
    struct sockaddr_in address;
    uint8_t mac_address[6];
    uint8_t mac_address_len;
}DISCOVERED_DEVICE;

typedef struct RECV_INFO {
    struct sockaddr *source;
    int *fromLen;
    WSABUF *buf;
    OVERLAPPED *overlapped;
    DWORD *flags;
    DWORD *bytes_recv;

    SOCKET socket;
    HANDLE *handles;
    size_t hCount;
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

#define EF_ERROR 0x00000001
#define EF_INTERFACE_UPDATE 0x00000002
#define EF_SEND_MULTIPLE_PACKETS 0x00000004
#define EF_NEW_DEVICE 0x00000008
#define EF_TERMINATION 0x00000010
#define EF_OVERRIDE_IO 0x00000020
#define EF_WAKE_MANAGER 0x00000040

typedef struct EVENT_FLAG {
    volatile uint32_t event_flag;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
}EVENT_FLAG, EFLAG;

typedef struct SEND_ARGS {
    int port;
    uint32_t multicast_addr;
    EFLAG *flag;
    EFLAG *wake;
    SOCKET_LL *sockets;
}SEND_ARGS;

typedef struct RECV_ARGS {

}RECV_ARGS;

typedef struct INTERFACE_UPDATE_ARGS {
    EFLAG *flag;
    EFLAG *wake;
    HANDLE termination_handle;
}INTERFACE_UPDATE_ARGS;


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

int send_discovery_packets(int port, uint32_t multicast_addr, SOCKET_LL *sockets, EFLAG *flag, uint32_t pCount, int32_t msec);
int register_single_discovery_receiver(SOCKET sock, RECV_INFO **info);
int register_multiple_discovery_receivers(SOCKET_LL *sockets, RECV_ARRAY *info, EFLAG *flag);


/////////////////////////////////////////////////////////////
///                                                       ///
///                  IO_HELPER_FUNCTIONS                  ///
///                                                       ///
/////////////////////////////////////////////////////////////

void prep_discovery_packet(DISCV_PAC *packet, const unsigned pac_type);
int create_handle_array_from_send_info(const SEND_INFO *info, size_t infolen, HANDLE **handles, size_t *hCount);
int create_handle_array_from_recv_info(dyn_array *info, HANDLE **handles, size_t *hCount);
void free_send_info(const SEND_INFO *info);
int allocate_recv_info(RECV_INFO **info);
int allocate_recv_info_fields(RECV_INFO *info);
void free_recv_info(const RECV_INFO *info);

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

void *send_discovery_thread(void *arg);
void *recv_discovery_thread(void *arg);
void *overlapped_io_handler_thread(void *arg);
void *interface_updater_thread(void *arg);
void *discovery_manager_thread(void *arg);


////////////////////////////////////////////////////////////////////
///                                                              ///
///                  general_use_functions/misc                  ///
///                                                              ///
////////////////////////////////////////////////////////////////////

void print_discovered_device_info(const DISCOVERED_DEVICE *dev, FILE *stream);


//////////////////////////////////////////////////////////////
///                                                        ///
///                  EVENT_FLAG_UTILITIES                  ///
///                                                        ///
//////////////////////////////////////////////////////////////

//to dynamically create an event flag
EFLAG *create_event_flag();
int free_event_flag(EFLAG *event_flag);
//to create stack based event flags (works fine with heap memory but allocation and freeing should be done manually)
int init_event_flag(EFLAG *event_flag);
int destroy_event_flag(EFLAG *event_flag);
//setters getters re-setters
int set_event_flag(EFLAG *event_flag, uint32_t flag_value);
int update_event_flag(EFLAG *event_flag, uint32_t flag_value);
int reset_event_flag(EFLAG *event_flag);
uint32_t get_event_flag(EFLAG *event_flag);
uint8_t termination_is_on(EFLAG *event_flag);

#endif //NETWERK_DEVICE_DISCOVERY_H
