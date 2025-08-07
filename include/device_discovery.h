//
// Created by Κωνσταντίνος on 4/16/2025.
//
//todo-> define the error codes after the system is completed
#ifndef NETWERK_DEVICE_DISCOVERY_H
#define NETWERK_DEVICE_DISCOVERY_H

#ifndef ON
#define ON 1
#endif

#ifndef OFF
#define OFF 0
#endif

#define DEVICE_TIME_UNTIL_DISCONNECTED 90

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

#define DISCOVERY_SEND_PERIOD_SEC 10

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

typedef struct DISCOVERED_DEVICE_NODE {
    DISCOVERED_DEVICE device;
    struct DISCOVERED_DEVICE_NODE *next;
}DISCOVERED_DEVICE_NODE, DEVICE_NODE;

typedef struct DISCOVERED_DEVICE_LIST {
    DEVICE_NODE *head;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
}DISCOVERED_DEVICE_LIST, DEVICE_LIST;

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
    DEVICE_LIST *devices;
}PACKET_HANDLER_ARGS;

typedef struct MANAGER_ARGS {
    int port;
    uint32_t multicast_addr;
    EFLAG *flag;
    DEVICE_LIST *devices;

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
void free_send_info(const SEND_INFO *info);
int allocate_recv_info(RECV_INFO **info);
int allocate_recv_info_fields(RECV_INFO *info);
void free_recv_info(const RECV_INFO *info);

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int *send_discovery_thread(SEND_ARGS *args);
int *recv_discovery_thread(RECV_ARGS *args);
int *discovery_packet_handler_thread(PACKET_HANDLER_ARGS *args);
uint8_t *interface_updater_thread(INTERFACE_UPDATE_ARGS *args);
int *discovery_manager_thread(MANAGER_ARGS *args);


///////////////////////////////////////////////////////////////////
///                                                             ///
///                  THREAD_CREATING_FUNCTIONS                  ///
///                                                             ///
///////////////////////////////////////////////////////////////////

#define init_device_discovery create_device_discovery_manager_thread
int cancel_device_discovery(pthread_t tid, EFLAG *flag);

int create_device_discovery_manager_thread(MANAGER_ARGS **args, int port, uint32_t multicast_address, DEVICE_LIST *devices, pthread_t *tid);
int create_discovery_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, SOCKET_LL *sockets, EFLAG *wake_mngr, pthread_t *tid);
int create_discovery_receiving_thread(RECV_ARGS **args, SOCKET_LL *sockets, QUEUE *queue, EFLAG *wake_mngr, pthread_t *tid);
int create_interface_updater_thread(INTERFACE_UPDATE_ARGS **args, int port, uint32_t multicast_address, EFLAG *wake_mngr, SOCKET_LL *sockets, pthread_t *tid);
int create_packet_handler_thread(PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *queue, DEVICE_LIST *dev_list, pthread_t *tid);


/////////////////////////////////////////////////////////////////
///                                                           ///
///                  THREAD_FUNCTION_HELPERS                  ///
///                                                           ///
/////////////////////////////////////////////////////////////////

int create_handle_array_from_recv_info(const RECV_ARRAY *info, HANDLE **handles, size_t *hCount);
void free_recv_array(const RECV_ARRAY *info);


////////////////////////////////////////////////////////////////////
///                                                              ///
///                  general_use_functions/misc                  ///
///                                                              ///
////////////////////////////////////////////////////////////////////

void print_discovered_device_info(const DISCOVERED_DEVICE *dev, FILE *stream);


//////////////////////////////////////////////////////////////
///                                                        ///
///                  DEVICE_LL_UTILITIES                   ///
///                                                        ///
//////////////////////////////////////////////////////////////

//they are thread unsafe, first lock the mutex and then use

int remove_device(DEVICE_LIST *devices, const DISCOVERED_DEVICE *dev);
DEVICE_NODE *device_exists(const DEVICE_LIST *devices, const DISCOVERED_DEVICE *dev);

#endif //NETWERK_DEVICE_DISCOVERY_H
