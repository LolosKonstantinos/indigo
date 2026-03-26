//
// Created by Constantin on 26/01/2026.
//

#ifndef NET_MONITOR_H
#define NET_MONITOR_H
#include <indigo_types.h>
#include <event_flags.h>
//for now, it's ok, later we will need to add linux libraries
#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#endif

/*todo implement a handle type of thing with the sockets so that on socket updates all services dont need
 *     to update them manually and when an interface is no longer available (no socket) the handle is just
 *     invalid and handled like a soft error and we recover without a complete shutdown
 */

typedef struct ip_subnet_t {
    uint32_t ip;
    uint32_t mask;
    IFTYPE interface_type;
}ip_subnet_t;

//for get_discovery_sockets()
typedef struct socket_ll_node {
    struct socket_ll_node *next;
    SOCKET sock;
    ip_subnet_t ip_subnet;
    uint32_t zero;
}socket_node;

typedef struct socket_ll {
    socket_node *head;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
}socket_ll;

typedef struct INTERFACE_UPDATE_ARGS {
    EFLAG *flag;
    EFLAG *override_flags[3];
    EFLAG *wake;
    HANDLE termination_handle;
    socket_ll *sockets;
    int port;
    uint32_t multicast_addr;
}INTERFACE_UPDATE_ARGS;


///////////////////////////////////
//                               //
//     GET_DISCOVERY_SOCKETS     //
//                               //
///////////////////////////////////

//the function that creates a linked list of sockets used for the device discovery
socket_node *get_discovery_sockets(int port, uint32_t multicast_addr);
//free the sockets linked list
void free_discv_sock_ll(socket_node *firstnode);


/////////////////////////////////////////////
///                                       ///
///    get_discovery_sockets() helpers    ///
///                                       ///
/////////////////////////////////////////////

//creates an array of IP_SUBNET
int get_compatible_interfaces(ip_subnet_t **ip_subnet, size_t *count);
//creates a single socket node
socket_node *create_discv_sock_node();
//ip and subnet helpers
uint32_t sub_mask_8to32b(uint8_t mask_8b);
uint8_t ips_share_subnet(ip_subnet_t addr1, ip_subnet_t addr2);
uint8_t ip_in_any_subnet(ip_subnet_t addr, const ip_subnet_t *p_addrs, size_t num_addrs);

SOCKET ip_to_socket(uint32_t ip, const socket_ll *sockets);


//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int* interface_updater_thread(INTERFACE_UPDATE_ARGS* args);
#endif //NET_MONITOR_H
