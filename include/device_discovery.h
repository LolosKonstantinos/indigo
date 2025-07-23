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
#define DISCOVERY_PACKET_SIZE 64 //not very important but good to have
                                 //(MUST ALWAYS STAY UP TO DATE, things might break) not really but who knows
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
#define HOST_NAME_MAX_LENGTH 56

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
#include <errno.h>


#endif

//the packet that is sent to the multicast group
typedef struct DISCV_PAC{
    uint32_t magic_number;
    unsigned char pac_version;
    unsigned char pac_type;
    uint16_t pac_length;
    unsigned char hostname[56];
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
    unsigned char name[56];
    time_t timestamp;
    struct sockaddr_in address;
    uint8_t mac_address[6];
    uint8_t mac_address_len;
}DISCOVERED_DEVICE;

typedef struct RECV_DATA {
    struct sockaddr *source;
    int *fromLen;
    WSABUF *buf;
    OVERLAPPED *overlapped;
    DWORD *flags;
    DWORD *bytes_recv;

    SOCKET socket;

    struct RECV_DATA *next;
}RECV_DATA;

//____GET_DISCOVERY_SOCKETS____//
//the function that creates a linked list of sockets used for the device discovery
SOCKET_NODE *get_discovery_sockets(int port, uint32_t multicast_addr);
//free the sockets linked list
void free_discv_sock_ll(SOCKET_NODE *firstnode);

//____get_discovery_sockets() helpers____//
//creates an array of IP_SUBNET
int get_compatible_interfaces(IP_SUBNET **ip_subnet, size_t *count);
//creates a single socket node
SOCKET_NODE *create_discv_sock_node();
//ip and subnet helpers
uint32_t sub_mask_8to32b(uint8_t mask_8b);
uint8_t ips_share_subnet(IP_SUBNET addr1, IP_SUBNET addr2);
uint8_t ip_in_any_subnet(IP_SUBNET addr, const IP_SUBNET *p_addrs, size_t num_addrs);


//____IO_FUNCTIONS____//
int send_discovery_packet(int port, uint32_t multicast_addr,SOCKET socket);


//____general_use_functions/misc____//
void prep_discovery_packet(DISCV_PAC *packet, const unsigned pac_type);
void print_discovered_device_info(DISCOVERED_DEVICE *dev, FILE *stream);


#endif //NETWERK_DEVICE_DISCOVERY_H
