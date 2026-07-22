/*Copyright (c) 2026 Lolos Konstantinos

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

#include "event_flags.h"
#include <indigo_core/net_monitor.h>
#include <indigo_errors.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <log.h>
#include <errno.h>
#ifndef _WIN32
#define INVALID_SOCKET (-1)
#endif
#ifdef __linux__
#include <asm/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#endif
///////////////////////////////////
//                               //
//     GET_DISCOVERY_SOCKETS     //
//                               //
///////////////////////////////////
///
/*Creates a link list of sockets used for device discovery
 *the sockets are bound to IPs of different subnets covering the maximum network area.
 *Priority is given to IPs of ethernet adapters over Wi-Fi adapters
 *returns a pointer to the first node else returns NULL
 */

#ifdef _WIN32
socket_node *get_discovery_sockets(const int port, const uint32_t multicast_addr)
{
    socket_node *new_sock = NULL;
    socket_node *first_sock = NULL;
    socket_node *temp_sock = NULL;
    ip_subnet_t *p_ip_subnet = NULL;
    size_t addr_count = 0;
    struct sockaddr_in server; // TODO: find better name
    struct ip_mreq mreq;       // the structure for the IP_ADD_MEMBERSHIP socket option
    DWORD optval = 0;          // the optval for the IP_MULTICAST_LOOP
    // initialize the multicast address
    mreq.imr_multiaddr.S_un.S_addr = multicast_addr;
    int err;

    err = get_compatible_interfaces(&p_ip_subnet, &addr_count);
    if (err != INDIGO_SUCCESS) {
        fprintf(stderr, "get_compatible_interfaces failed in get_discovery_sockets\n");
        return NULL;
    }

    if (p_ip_subnet == NULL) {
        fprintf(stderr, "NO VALID INTERFACE FOUND...\n");
        return NULL;
    }

    for (int i = 0; i < addr_count; i++) {
        // create new node
        new_sock = create_discv_sock_node();
        if (new_sock == NULL) {
            fprintf(stderr, "Failed to create disc node\n");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);

            return NULL;
        }
        // connect node to linked list
        if (first_sock != NULL && temp_sock != NULL) {
            temp_sock->next = new_sock;
            temp_sock = new_sock;
        }
        else {
            first_sock = new_sock;
            temp_sock = new_sock;
        }
        memcpy(&(new_sock->ip_subnet), &(p_ip_subnet[i]), sizeof(ip_subnet_t));

        // bind the socket to the local address (one for every address found)
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = port;
        server.sin_addr.s_addr = p_ip_subnet[i].ip;

        err = bind(new_sock->sock, (struct sockaddr *)(&server), sizeof(server));
        if (err == SOCKET_ERROR) {
            perror("Failed to bind disc node");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            return NULL;
        }

        mreq.imr_interface.s_addr = server.sin_addr.s_addr;
        err = setsockopt(new_sock->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
        if (err == SOCKET_ERROR) {
            perror("Failed to add membership");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            return NULL;
        }

        err = setsockopt(new_sock->sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&optval, sizeof(optval));
        if (err == SOCKET_ERROR) {
            perror("Failed to set multicast loop");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            return NULL;
        }
    }

    // we don't need the ip list anymore
    free(p_ip_subnet);

    return first_sock;
}

/*Closes all sockets in the linked list and frees the allocated memory for the list*/
void free_discv_sock_ll(socket_node *firstnode)
{
    socket_node *curr;
    socket_node *next;

    if (firstnode == NULL)
        return;

    curr = firstnode;
    while (curr != NULL) {
        next = curr->next;
        closesocket(curr->sock);
        free(curr);
        curr = next;
    }
}

/////////////////////////////////////////////////////
///                                               ///
///        get_discovery_sockets() helpers        ///
///                                               ///
/////////////////////////////////////////////////////

// creates an array of the compatible IPs and the respective subnet masks.
// the minimum amount of separate interfaces and higher speed is ensured.
// returns 0 on success and non-zero on failure
int get_compatible_interfaces(ip_subnet_t **ip_subnet, size_t *count)
{
    void *temp = NULL;
    PIP_ADAPTER_ADDRESSES adapter = NULL;
    PIP_ADAPTER_ADDRESSES p = 0;
    ULONG size = 17500; // 17.5KB to be allocated for GetAdaptersAddresses, it's the recommended microsoft method
    ULONG err = 0;
    ULONG flags;
    ip_subnet_t *p_ip_subnet = NULL;
    ip_subnet_t temp_ip_subnet;
    int addr_count = 0;

    // allocate memory for the adapters
    adapter = malloc(size);
    if (adapter == NULL) {
        perror("Failed to allocate memory for adapter_addresses");
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    // prepare GetAdaptersAddresses flags
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    // if the allocated memory is not enough reallocate
    err = GetAdaptersAddresses(AF_INET, flags, NULL, adapter, &size);
    if (err != ERROR_SUCCESS) {
        // if we get a buffer overflow we reallocate
        while (err == ERROR_BUFFER_OVERFLOW) {
            temp = realloc(adapter, size);
            if (temp == NULL) {
                perror("Failed to allocate memory for adapter_addresses");
                free(adapter);
                return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            }
            adapter = temp;
            err = GetAdaptersAddresses(AF_INET, flags, NULL, adapter, &size);
        }

        if (err == ERROR_ADDRESS_NOT_ASSOCIATED) {
            for (int j = 0; j < 50; j++) {
                Sleep(100);
                err = GetAdaptersAddresses(AF_INET, flags, NULL, adapter, &size);
                if (err != ERROR_ADDRESS_NOT_ASSOCIATED)
                    break;
            }
            if (err == ERROR_ADDRESS_NOT_ASSOCIATED) {
                fprintf(stderr, "GetAdaptersAddresses failed in get_compatible_interfaces addr not associated\n");
                free(adapter);
                return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            }
        }

        if (err == ERROR_INVALID_PARAMETER) {
            fprintf(stderr, "Invalid parameters in GetAdaptersAddresses() call in get_compatible_interfaces\n");
            fprintf(stderr, "its a buuuuuuuuuuuugggggg!\n");
            free(adapter);
            return INDIGO_ERROR_INVALID_PARAM;
        }

        if (err == ERROR_NOT_ENOUGH_MEMORY) {
            fprintf(stderr, "NOT ENOUGH MEMORY!\n");
            free(adapter);
            return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        }

        if (err == ERROR_NO_DATA) {
            free(adapter);
            return INDIGO_ERROR_NO_ADDRESS_FOUND;
        }

        // if we get another error we return
        if (err != ERROR_SUCCESS) {
            fprintf(stderr, "GetAdaptersAddresses failed.%lu\n", err);
            free(adapter);
            return INDIGO_ERROR_WINLIB_ERROR;
        }
    }

    // go through all the adapters
    for (p = adapter; p != NULL; p = p->Next) {
        // adapters must be Wi-Fi or Ethernet and must be active
        if (((p->IfType == IF_TYPE_ETHERNET_CSMACD) || (p->IfType == IF_TYPE_IEEE80211)) &&
            (p->OperStatus == IfOperStatusUp)) {
            // go through all the unicast addresses of the adapter
            for (PIP_ADAPTER_UNICAST_ADDRESS unicast_addr = p->FirstUnicastAddress; unicast_addr != NULL;
                 unicast_addr = unicast_addr->Next) {
                if (unicast_addr->Flags == IP_ADAPTER_ADDRESS_TRANSIENT)
                    continue;

                // fill the ip, subnet mask, and interface type
                temp_ip_subnet.ip =
                    ntohl((((struct sockaddr_in *)((unicast_addr->Address).lpSockaddr))->sin_addr).S_un.S_addr);
                temp_ip_subnet.mask = sub_mask_8to32b(unicast_addr->OnLinkPrefixLength);
                temp_ip_subnet.interface_type = p->IfType;

                // check if the current unicast is in the same subnet as some other address
                if (!ip_in_any_subnet(temp_ip_subnet, p_ip_subnet, addr_count)) {
                    // create more space for 1 more subnet
                    temp = realloc(p_ip_subnet, sizeof(ip_subnet) * (addr_count + 1));
                    if (temp == NULL) {
                        perror("Failed to reallocate memory for ip_subnet_t");
                        free(adapter);
                        free(p_ip_subnet);
                        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    }
                    p_ip_subnet = temp;
                    // store the new-found subnet
                    p_ip_subnet[addr_count] = temp_ip_subnet;
                    // update the length of the dynamic array
                    addr_count++;
                }
                // prioritize ethernet over Wi-Fi
                // replaces any Wi-Fi address with an ethernet one of the same subnet
                else if (p_ip_subnet && ip_in_any_subnet(temp_ip_subnet, p_ip_subnet, addr_count) &&
                         p->IfType == IF_TYPE_ETHERNET_CSMACD) {
                    // the p_ip_subnet condition is pointless, because ip_in_any_subnet would return 0 if p_ip_subnet is
                    // NULL put it there because clang cries, though is pintless
                    for (int i = 0; i < addr_count; i++) {
                        if (p_ip_subnet[i].interface_type == IF_TYPE_IEEE80211) {
                            if (ips_share_subnet(p_ip_subnet[i], temp_ip_subnet))
                                p_ip_subnet[i] = temp_ip_subnet;
                        }
                    }
                }
            }
        }
    }

    *ip_subnet = p_ip_subnet;
    *count = addr_count;
    free(adapter);
    return INDIGO_SUCCESS;
}

/*  Create a discovery socket linked list node.(a linked list of sockets that send discovery packets. one per adapter)
 *the sockets are semi configured, the rest configuration is done while creating the linked list of discv_sockets
 *(because we need to limit calls to getAdaptersAddresses() not time and space efficient)
 *
 *Returns a pointer to the node created. If it fails it returns NULL.
 */
socket_node *create_discv_sock_node()
{
    char optval = 1;
    DWORD ttl = 1;
    socket_node *node = malloc(sizeof(socket_node));

    if (node == NULL) {
        perror("Failed to allocate memory for DISCV_SOCK");
        return NULL;
    }

    node->next = NULL;
    node->sock = WSASocketA(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0x01);
    if (node->sock == INVALID_SOCKET) {
        printf("\nFailed to create socket: %lu\n", GetLastError());
        free(node);
        return NULL;
    }

    if (setsockopt(node->sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
        perror("setsockopt() SO_REUSEADDR failed");
        closesocket(node->sock);
        free(node);
        return NULL;
    }

    // set time to live to 1 --> local network, cant be routed
    if (setsockopt(node->sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&ttl, sizeof(ttl)) != 0) {
        perror("setsockopt() IP_MULTICAST_TTL failed");
        closesocket(node->sock);
        free(node);
        return NULL;
    }

    return node;
}
#else
socket_node *get_discovery_sockets(int port, uint32_t multicast_addr)
{
    socket_node *new_sock = NULL;
    socket_node *first_sock = NULL;
    socket_node *temp_sock = NULL;
    ip_subnet_t *p_ip_subnet = NULL;
    size_t addr_count = 0;
    struct sockaddr_in interface;
    struct ip_mreq mreq;       // the structure for the IP_ADD_MEMBERSHIP socket option
    int optval = 0;            // the optval for the IP_MULTICAST_LOOP
    // initialize the multicast address
    mreq.imr_multiaddr.s_addr = multicast_addr;
    int err;

    err = get_compatible_interfaces(&p_ip_subnet, &addr_count);
    if (err != INDIGO_SUCCESS) {
        log_error("[get_discovery_sockets] get_compatible_interfaces failed | return NULL");
        return NULL;
    }

    if (p_ip_subnet == NULL) {
        log_warn( "[get_discovery_sockets] NO VALID INTERFACE FOUND...");
        return NULL;
    }

    for (int i = 0; i < addr_count; i++) {
        // create new node
        new_sock = create_discv_sock_node();
        if (new_sock == NULL) {
            log_error( "[get_discovery_sockets] create_discv_sock_node() failed to create socket linked list node | return NULL");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);

            return NULL;
        }
        // connect node to linked list
        if (first_sock != NULL && temp_sock != NULL) {
            temp_sock->next = new_sock;
            temp_sock = new_sock;
        }
        else {
            first_sock = new_sock;
            temp_sock = new_sock;
        }
        new_sock->ip_subnet.interface_type = p_ip_subnet->interface_type;
        new_sock->ip_subnet.ip = p_ip_subnet->ip;
        new_sock->ip_subnet.mask = p_ip_subnet->mask;
        log_debug("[get_discovery_sockets] interface:%d mask:%d", new_sock->ip_subnet.ip, new_sock->ip_subnet.mask);

        // bind the socket to the local address (one for every address found)
        memset(&interface, 0, sizeof(interface));
        interface.sin_family = AF_INET;
        interface.sin_port = port;
        interface.sin_addr.s_addr = p_ip_subnet[i].ip;

        err = bind(new_sock->sock, (struct sockaddr *)(&interface), sizeof(interface));
        if (err) {
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            log_error("[get_discovery_sockets] bind() failed to bind socket | return NULL | errno %d", errno);
            return NULL;
        }

        mreq.imr_interface.s_addr = interface.sin_addr.s_addr;
        err = setsockopt(new_sock->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
        if (err) {
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            log_error("[get_discovery_sockets] setsockopt() failed to add multicast membership | return NULL | errno %d", errno);
            return NULL;
        }

        err = setsockopt(new_sock->sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&optval, sizeof(optval));
        if (err) {
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            log_error("[get_discovery_sockets] setsockopt() failed to turn off multicast packet loopback | return NULL | errno %d", errno);
            return NULL;
        }
    }

    // we don't need the ip list anymore
    free(p_ip_subnet);

    return first_sock;
}

int get_compatible_interfaces(ip_subnet_t **ip_subnet, size_t *count)
{
    void *temp;
    int ret;
    ip_subnet_t *p_ip_subnet = NULL;
    ip_subnet_t temp_ip_subnet;
    int addr_count = 0;
    unsigned int flags = 0;
    int family;
    struct sockaddr_in *saddr;
    struct ifaddrs *ifap = NULL;
    char interface_wireless_path[PATH_MAX];
    char interface_type = -1;

    ret = getifaddrs(&ifap);
    if (ret) {
        log_error("[get_compatible_interfaces] getifaddrs() failed | return %d | errno %d", INDIGO_ERROR, errno);
        return INDIGO_ERROR;
    }
    if (ifap == NULL) {
        log_error("[get_compatible_interfaces] no interface data linked list returned | return %d | errno %d",
            INDIGO_ERROR_NO_ADDRESS_FOUND, errno);
        return INDIGO_ERROR_NO_ADDRESS_FOUND;
    }
    for (struct ifaddrs *i = ifap; i != NULL; i = i->ifa_next) {
        if (i->ifa_addr == NULL || i->ifa_netmask == NULL)
            continue;
        flags = i->ifa_flags;
        family = i->ifa_addr->sa_family;
        saddr = (struct sockaddr_in *)i->ifa_addr;

        if (flags & IFF_LOOPBACK)
            continue;
        if (family == AF_INET6)
            continue;

        if (flags & IFF_UP) {
            // find the interface_type
            snprintf(interface_wireless_path, PATH_MAX, "/sys/class/net/%s/wireless", i->ifa_name);

            if (access(interface_wireless_path, F_OK) == 0) {
                interface_type = 1;
            }
            else {
                interface_type = 0;
            }

            // check if the current unicast is in the same subnet as some other address
            temp_ip_subnet.ip = saddr->sin_addr.s_addr;
            saddr = (struct sockaddr_in *)i->ifa_netmask;
            temp_ip_subnet.mask = saddr->sin_addr.s_addr;
            temp_ip_subnet.interface_type = (int)interface_type;

            if (!ip_in_any_subnet(temp_ip_subnet, p_ip_subnet, addr_count)) {
                // create more space for 1 more subnet
                temp = realloc(p_ip_subnet, sizeof(ip_subnet_t) * (addr_count + 1));
                if (temp == NULL) {
                    log_error("[get_compatible_interfaces] Failed to reallocate memory for ip_subnet_t | return %d",
                        INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
                    free(p_ip_subnet);
                    freeifaddrs(ifap);
                    return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                }
                p_ip_subnet = temp;
                // store the new-found subnet
                p_ip_subnet[addr_count] = temp_ip_subnet;
                // update the length of the dynamic array
                addr_count++;
            }
            // prioritize ethernet over Wi-Fi
            // replaces any Wi-Fi address with an ethernet one of the same subnet
            else if (p_ip_subnet && ip_in_any_subnet(temp_ip_subnet, p_ip_subnet, addr_count) && interface_type == 0) {
                // the p_ip_subnet condition is pointless, because ip_in_any_subnet would return 0 if p_ip_subnet is
                // NULL put it there because clang cries, though is pintless
                for (int j = 0; j < addr_count; j++) {
                    if (p_ip_subnet[j].interface_type == 1) {
                        if (ips_share_subnet(p_ip_subnet[j], temp_ip_subnet))
                            p_ip_subnet[j] = temp_ip_subnet;
                    }
                }
            }
        }
    }
    *ip_subnet = p_ip_subnet;
    *count = addr_count;
    freeifaddrs(ifap);
    return 0;
}

socket_node *create_discv_sock_node()
{
    int optval = 1;
    int ttl = 1;

    socket_node *node = malloc(sizeof(socket_node));
    if (node == NULL) {
        log_error("[create_discv_sock_node] malloc() failed allocating %d bytes for socket_node | return NULL", sizeof(socket_node));
        return NULL;
    }

    node->next = NULL;
    node->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (node->sock == INVALID_SOCKET) {
        log_error("[create_discv_sock_node] socket() failed to create socket | return NULL | errno %d", errno);
        free(node);
        return NULL;
    }

    if (setsockopt(node->sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
        log_error("[create_discv_sock_node] setsockopt() SO_REUSEADDR failed | return NULL | errno %d", errno);
        close(node->sock);
        free(node);
        return NULL;
    }

    // set time to live to 1 --> local network, cant be routed
    if (setsockopt(node->sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&ttl, sizeof(ttl)) != 0) {
        log_error("[create_discv_sock_node] setsockopt() IP_MULTICAST_TTL failed | return NULL | errno %d", errno);
        close(node->sock);
        free(node);
        return NULL;
    }
    log_debug("[create_discv_sock_node] created socket %d", node->sock);

    return node;
}
void free_discv_sock_ll(socket_node *firstnode)
{
    socket_node *curr;
    socket_node *next;

    if (!firstnode) {
        return;
    }

    curr = firstnode;
    while (curr != NULL) {
        next = curr->next;
        close(curr->sock);
        free(curr);
        curr = next;
    }
}
#endif
//____IP AND SUBNET HELPERS____//

uint32_t sub_mask_8to32b(const uint8_t mask_8b)
{
    uint32_t mask_32b = 0;
    for (uint8_t j = 0; j < mask_8b; j++) {
        mask_32b |= 1;
        mask_32b <<= 1;
    }
    for (int i = 0; i < 32 - mask_8b - 1; i++) {
        mask_32b <<= 1;
    }
    return mask_32b;
}

uint8_t ips_share_subnet(const ip_subnet_t addr1, const ip_subnet_t addr2)
{
    return ((addr1.ip & addr1.mask) == (addr2.ip & addr2.mask));
}

uint8_t ip_in_any_subnet(const ip_subnet_t addr, const ip_subnet_t *p_addrs, const size_t num_addrs)
{
    if (p_addrs == NULL)
        return 0;
    for (int i = 0; i < num_addrs; i++) {
        if (ips_share_subnet(addr, p_addrs[i]))
            return 1;
    }
    return 0;
}

#ifdef _WIN32
SOCKET ip_to_socket(const uint32_t ip, const socket_ll *const sockets)
{
    ip_subnet_t sub;
    if (sockets == NULL)
        return INVALID_SOCKET;

    for (socket_node *node = sockets->head; node; node = node->next) {
        sub = node->ip_subnet;
        if ((ip & sub.mask) == (sub.ip & sub.mask)) {
            return node->sock;
        }
    }
    return INVALID_SOCKET;
}
#else
int ip_to_socket(const uint32_t ip, const socket_ll *const sockets)
{
    ip_subnet_t sub;
    if (sockets == NULL)
        return -1;

    for (socket_node *node = sockets->head; node; node = node->next) {
        sub = node->ip_subnet;
        if ((ip & sub.mask) == (sub.ip & sub.mask)) {
            return node->sock;
        }
    }
    return -1;
}
#endif

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

#ifdef _WIN32
int *interface_updater_thread(INTERFACE_UPDATE_ARGS *args)
{
    HANDLE notification_handle = NULL;
    HANDLE handles[2];
    WSAOVERLAPPED overlapped = {0};
    DWORD ret_val;
    int *process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        printf("DEBUG: update exit\n");
        fflush(stdout);
        return NULL;
    }
    *process_return = 0;

    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL) {
        perror("WSACreateEvent() failed in device_discovery_sending");
        *process_return = INDIGO_ERROR_WINLIB_ERROR;
        set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        printf("DEBUG: update exit\n");
        fflush(stdout);
        return process_return;
    }

    // initialize the array of handles
    handles[0] = args->termination_handle;
    handles[1] = overlapped.hEvent;

    // register for address changes
    ret_val = NotifyAddrChange(&notification_handle, &overlapped);
    if (ret_val != ERROR_IO_PENDING) {
        fprintf(stderr, "NotifyAddrChange() failed in interface_updater\n");
        // print what the fuzz is about
        switch (ret_val) {
            case ERROR_INVALID_PARAMETER:
                fprintf(stderr, "ERROR_INVALID_PARAMETER\n");
                *process_return = INDIGO_ERROR_INVALID_STATE;
                break;
            case ERROR_NOT_ENOUGH_MEMORY:
                fprintf(stderr, "ERROR_NOT_ENOUGH_MEMORY\n");
                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                break;
            case ERROR_NOT_SUPPORTED:
                fprintf(stderr, "ERROR_NOT_SUPPORTED\n");
                *process_return = INDIGO_ERROR_UNSUPPORTED;
                break;
            default:
                break;
        }

        set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        printf("DEBUG: update exit\n");
        fflush(stdout);
        return process_return;
    }

    // the main loop
    while (!termination_is_on(args->flag)) {
        // the function blocks here and waits for an event
        printf("DEBUG: entered waiting\n");
        fflush(stdout);
        // todo: do not use infinite, to prevent deadlock or something, use big number
        ret_val = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        printf("DEBUG: exited waiting\n");
        fflush(stdout);
        // error check
        if (ret_val == WAIT_FAILED) {
            perror("WaitForMultipleObjects() failed in interface_updater");
            *process_return = INDIGO_ERROR_WINLIB_ERROR;
            set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            printf("DEBUG: update exit\n");
            fflush(stdout);
            return process_return;
        }
        // check which event was signaled
        if (ret_val - WAIT_OBJECT_0 == 1) {
            // interface update
            printf("DEBUG: interface update\n");
            fflush(stdout);

            // raise the override flags of the io threads
            for (int i = 0; i < 3; i++) {
                set_event_flag(args->override_flags[i], EF_WAKE_MANAGER);
            }
            WSAResetEvent(overlapped.hEvent);

            pthread_mutex_lock(&(args->sockets->mutex));
            free_discv_sock_ll(args->sockets->head);
            args->sockets->head = get_discovery_sockets(args->port, args->multicast_addr);
            if (args->sockets->head == NULL) {
                // no discovery sockets, no device discovery
                set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                *process_return = INDIGO_ERROR_NO_ADDRESS_FOUND;
                pthread_mutex_unlock(&(args->sockets->mutex));
                printf("DEBUG: update exit\n");
                fflush(stdout);
                return process_return;
            }
            pthread_mutex_unlock(&(args->sockets->mutex));
            // lower the override flag for the io threads
            for (int i = 0; i < 3; i++) {
                reset_single_event(args->override_flags[i], EF_OVERRIDE_IO);
            }
            // re-register for address changes
            ret_val = NotifyAddrChange(&notification_handle, &overlapped);
            if (ret_val != ERROR_IO_PENDING) {
                fprintf(stderr, "NotifyAddrChange() failed in interface_updater\n");
                // print what the fuzz is about
                switch (ret_val) {
                    case ERROR_INVALID_PARAMETER:
                        fprintf(stderr, "ERROR_INVALID_PARAMETER\n");
                        *process_return = INDIGO_ERROR_INVALID_STATE;
                        break;
                    case ERROR_NOT_ENOUGH_MEMORY:
                        fprintf(stderr, "ERROR_NOT_ENOUGH_MEMORY\n");
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        break;
                    case ERROR_NOT_SUPPORTED:
                        fprintf(stderr, "ERROR_NOT_SUPPORTED\n");
                        *process_return = INDIGO_ERROR_UNSUPPORTED;
                        break;
                    default:
                        break;
                }

                set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                printf("DEBUG: update exit\n");
                fflush(stdout);
                return process_return;
            }
        }
        else if (ret_val - WAIT_OBJECT_0 == 0) {
            // termination event
            CancelIPChangeNotify(&overlapped);
            printf("DEBUG: update exit\n");
            fflush(stdout);
            return process_return;
        }
        else {
            // there is probably an error
            fprintf(stderr, "WaitForMultipleObjects() failed in interface_updater: %d\n", WSAGetLastError());

            set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            CancelIPChangeNotify(&overlapped);
            *process_return = INDIGO_ERROR_INVALID_STATE;
            printf("DEBUG: update exit\n");
            fflush(stdout);
            return process_return;
        }
    }
    // termination event signaled and loop ended
    printf("DEBUG: update exit\n");
    fflush(stdout);

    CancelIPChangeNotify(&overlapped);
    return process_return;
}
#else
int *interface_updater_thread(INTERFACE_UPDATE_ARGS *args)
{
    int ret;
    int sock = -1;
    struct sockaddr_nl sa;
    struct nlmsghdr buf[8192 / sizeof(struct nlmsghdr)];
    struct iovec iov = {buf, sizeof(buf)};
    struct msghdr msg;
    struct nlmsghdr *nh;
    ssize_t size;
    int epoll_fd = -1;
    struct epoll_event event = {0};
    uint64_t termination_val;

    int *process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        log_fatal("[interface_updater_thread] malloc failed allocating %d bytes for process return | return NULL", sizeof(int));
        return NULL;
    }
    *process_return = INDIGO_SUCCESS;

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        *process_return = INDIGO_ERROR;
        log_fatal("[interface_updater_thread] socket() failed opening netlink socket | return %d | errno %d", *process_return, errno);
        goto cleanup;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;
    ret = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (ret) {
        *process_return = INDIGO_ERROR;
        log_fatal("[interface_updater_thread] bind() failed binding socket | return %d | errno %d", *process_return, errno);
        goto cleanup;
    }
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        *process_return = INDIGO_ERROR_SYS_FAIL;
        log_fatal("[interface_updater_thread] epoll_create1() failed | return %d | errno %d", *process_return, errno);
        goto cleanup;
    }

    event.events = EPOLLIN;
    event.data.fd = args->termination_fd;
    event.data.u32 = 1;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, args->termination_fd, &event) == -1) {
        *process_return = INDIGO_ERROR;
        log_fatal("[interface_updater_thread] epoll_ctl() failed adding termination file descriptor | return %d | errno %d", *process_return, errno);
        goto cleanup;
    }
    event.events = EPOLLIN;
    event.data.fd = sock;
    event.data.u32 = 0;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &event) == -1) {
        *process_return = INDIGO_ERROR;
        log_fatal("[interface_updater_thread] epoll_ctl() failed adding netlink socket | return %d | errno %d", *process_return, errno);
        goto cleanup;
    }

    msg = (struct msghdr){.msg_name = &sa,
        .msg_namelen = sizeof(sa),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0};

    // the main loop
    while (termination_is_on(args->flag) == 0) {
        ret = epoll_wait(epoll_fd, &event, 1, 10000);
        if (ret >= 1) {
            // if it is a netlink event
            if (event.data.u32 == 0) {
                log_debug("[interface_updater_thread] interface update");
                ret = 0;
                size = recvmsg(sock, &msg, 0);
                if (size < 0) {
                    *process_return = INDIGO_ERROR;
                    log_fatal("[interface_updater_thread] recvmsg() failed receiving netlink update | return %d | errno %d",
                        *process_return, errno);
                    goto cleanup;
                }
                for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, size); nh = NLMSG_NEXT(nh, size)) {
                    if (nh->nlmsg_type == NLMSG_DONE) {
                        break;
                    }
                    if (nh->nlmsg_type == NLMSG_ERROR) {
                        // IDK do some error handling
                        continue;
                    }
                    ret = 1;
                }
                if (ret == 1) {
                    // in any case we need to update the socket list
                    // raise the override flags of the io threads
                    for (int i = 0; i < 3; i++) {
                        set_event_flag(args->override_flags[i], EF_OVERRIDE_IO);
                    }
                    pthread_mutex_lock(&(args->sockets->mutex));
                    free_discv_sock_ll(args->sockets->head);
                    args->sockets->head = get_discovery_sockets(args->port, args->multicast_addr);
                    if (args->sockets->head == NULL) {
                        // no discovery sockets, no device discovery
                        set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_NO_ADDRESS_FOUND;
                        pthread_mutex_unlock(&(args->sockets->mutex));
                        log_fatal("[interface_updater_thread] get_discovery_sockets() failed | return %d", *process_return);
                        goto cleanup;
                    }
                    pthread_mutex_unlock(&(args->sockets->mutex));
                    // lower the override flag for the io threads
                    for (int i = 0; i < 3; i++) {
                        reset_single_event(args->override_flags[i], EF_OVERRIDE_IO);
                    }
                }

            }
            else if (event.data.u32 == 1) {
                // termination event
                read(args->termination_fd, &termination_val, 8);
                if (termination_val == 1) {
                    *process_return = INDIGO_SUCCESS;
                    log_info("[interface_updater_thread] interface updater thread successful exit | return %d", *process_return);
                    goto cleanup;
                }
            }
        }
        else if (ret == -1) {
            // IDK cleanup;
            //this is a debug statement as it fails on SIGSTOP that the debugger sends
            if (errno == EINTR) continue;
            *process_return = INDIGO_ERROR;
            log_fatal("[interface_updater_thread] epoll_wait() failed while waiting for link updates | return %d | errno %d",
                *process_return, errno);
            goto cleanup;
        }

    }
    close(sock);
    close(epoll_fd);
    log_info("[interface_updater_thread] interface updater thread successful exit | return %d", *process_return);
    return process_return;
cleanup:
    if (sock >= 0)
        close(sock);
    if (epoll_fd >= 0)
        close(epoll_fd);
    return process_return;
}
#endif
