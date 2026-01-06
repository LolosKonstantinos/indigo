//
// Created by Κωνσταντίνος on 4/16/2025.
//

#include "device_discovery.h"
#include "buffer.h"
#include "indigo_errors.h"
#include <stdlib.h>
#include <errno.h>
#include <sodium.h>
#include "crypto_utils.h"

//todo split this library to the device discovery and the receiving and managing part
//todo ip banning should be done to the kernel level

/*Creates a link list of sockets used for device discovery
 *the sockets are bound to IPs of different subnets covering the maximum network area.
 *Priority is given to IPs of ethernet adapters over wi-fi adapters
 *returns a pointer to the first node else returns NULL
 */
SOCKET_NODE *get_discovery_sockets(const int port, const uint32_t multicast_addr) {
    SOCKET_NODE *new_sock = NULL, *first_sock = NULL, *temp_sock = NULL;
    IP_SUBNET *p_ip_subnet = NULL;
    size_t addr_count = 0;
    struct sockaddr_in server; //TODO: find better name
    struct ip_mreq mreq;//the structure for the IP_ADD_MEMBERSHIP socket option
    DWORD optval = 0; // the optval for the IP_MULTICAST_LOOP
    //initialize the multicast address
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
        //create new node
        new_sock = create_discv_sock_node();
        if (new_sock == NULL) {
            fprintf(stderr, "Failed to create disc node\n");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);

            return NULL;
        }

        //connect node to linked list
        if (first_sock != NULL && temp_sock != NULL) {
            temp_sock->next = new_sock;
            temp_sock = new_sock;
        }
        else {
            first_sock = new_sock;
            temp_sock = new_sock;
        }

        //bind the socket to the local address (one for every address found)
        memset(&server,0,sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = port;
        server.sin_addr.s_addr = htonl(p_ip_subnet[0].ip);

        err = bind(new_sock->sock,(struct sockaddr *)(&server),sizeof(server));
        if (err == SOCKET_ERROR) {
            perror("Failed to bind disc node");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            err = WSAGetLastError();
            return NULL;
        }

        mreq.imr_interface.S_un.S_addr = server.sin_addr.S_un.S_addr;
        err = setsockopt(new_sock->sock,IPPROTO_IP,IP_ADD_MEMBERSHIP,(char *)&mreq,sizeof(mreq));
        if (err == SOCKET_ERROR) {
            perror("Failed to add membership");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            return NULL;
        }

        err = setsockopt(new_sock->sock,IPPROTO_IP,IP_MULTICAST_LOOP,(char *)&optval,sizeof(optval));
        if (err == SOCKET_ERROR) {
            perror("Failed to set multicast loop");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            return NULL;
        }
    }

    //we don't need the ip list anymore
    free(p_ip_subnet);

    return first_sock;
}

/*Closes all sockets in the linked list and frees the allocated memory for the list*/
void free_discv_sock_ll(SOCKET_NODE *firstnode) {
    if (firstnode == NULL) return;

    SOCKET_NODE *curr, *next;

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

//creates an array of the compatible IPs and the respective subnet masks.
//the minimum amount of separate interfaces and higher speed is ensured.
//returns 0 on success and non-zero on failure
int get_compatible_interfaces(IP_SUBNET **ip_subnet, size_t *count) {
    void *temp = NULL;
    PIP_ADAPTER_ADDRESSES adapter = NULL,p =0;
    ULONG size = 17500; //17.5KB to be allocated for GetAdaptersAddresses, it's the recommended microsoft method
    ULONG err = 0;
    ULONG flags;
    IP_SUBNET *p_ip_subnet = NULL, temp_ip_subnet;
    int addr_count = 0;


    //allocate memory for the adapters
    adapter = malloc(size);
    if (adapter == NULL) {
        perror("Failed to allocate memory for adapter_addresses");
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    //prepare GetAdaptersAddresses flags
    flags = GAA_FLAG_SKIP_ANYCAST
    | GAA_FLAG_SKIP_MULTICAST
    | GAA_FLAG_SKIP_DNS_SERVER
    ;


    //if the allocated memory is not enough reallocate
    err = GetAdaptersAddresses(AF_INET,flags,NULL,adapter,&size);
    if (err != ERROR_SUCCESS) {
        //if we get a buffer overflow we reallocate
        while (err == ERROR_BUFFER_OVERFLOW){
            temp = realloc(adapter, size);
            if (temp == NULL) {
                perror("Failed to allocate memory for adapter_addresses");
                free(adapter);
                return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            }
            adapter = temp;
            err = GetAdaptersAddresses(AF_INET,flags,NULL,adapter,&size);
        }

        if (err == ERROR_ADDRESS_NOT_ASSOCIATED){
            for (int j = 0; j < 50; j++) {
                Sleep(100);
                err = GetAdaptersAddresses(AF_INET,flags,NULL,adapter,&size);
                if (err != ERROR_ADDRESS_NOT_ASSOCIATED) break;
            }
            if (err == ERROR_ADDRESS_NOT_ASSOCIATED) {
                fprintf(stderr, "GetAdaptersAddresses failed in get_compatible_interfaces addr not associated\n");
                free(adapter);
                return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            }
        }

        if (err == ERROR_INVALID_PARAMETER) {
            fprintf(stderr, "Invalid parameters in GetAdaptersAddresses() call in get_compatible_interfaces\n");
            fprintf(stderr,"its a buuuuuuuuuuuugggggg!\n");
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

        //if we get another error we return
        if (err != ERROR_SUCCESS) {
            fprintf(stderr,"GetAdaptersAddresses failed.%d\n",err);
            free(adapter);
            return INDIGO_ERROR_WINLIB_ERROR;
        }
    }

    //go through all the adapters
    for (p=adapter;p!=NULL;p=p->Next) {
        //adapters must be Wi-Fi or Ethernet and must be active
        if (((p->IfType == IF_TYPE_ETHERNET_CSMACD) || (p->IfType == IF_TYPE_IEEE80211)) && (p->OperStatus == IfOperStatusUp)){
            //go through all the unicast addresses of the adapter
            for (PIP_ADAPTER_UNICAST_ADDRESS unicast_addr = p->FirstUnicastAddress; unicast_addr != NULL; unicast_addr = unicast_addr->Next) {
                if (unicast_addr->Flags == IP_ADAPTER_ADDRESS_TRANSIENT) continue;

                //fill the ip, subnet mask, and interface type
                temp_ip_subnet.ip = ntohl((((struct sockaddr_in *)((unicast_addr->Address).lpSockaddr))->sin_addr).S_un.S_addr);
                temp_ip_subnet.mask = sub_mask_8to32b(unicast_addr->OnLinkPrefixLength);
                temp_ip_subnet.interface_type = p->IfType;

                //check if the current unicast is in the same subnet as some other address
                if (!ip_in_any_subnet(temp_ip_subnet,p_ip_subnet, addr_count)) {
                           //create more space for 1 more subnet
                    temp = realloc(p_ip_subnet, sizeof(IP_SUBNET) * (addr_count + 1));
                    if (temp == NULL) {
                        perror("Failed to reallocate memory for ip_subnet");
                        free(adapter);
                        free(p_ip_subnet);
                        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    }
                    p_ip_subnet = temp;
                    //store the new-found subnet
                    p_ip_subnet[addr_count] = temp_ip_subnet;
                    //update the length of the dynamic array
                    addr_count++;
                }
                //prioritize ethernet over wi-fi
                //replaces any wi-fi address with an ethernet one of the same subnet
                else if(p_ip_subnet && ip_in_any_subnet(temp_ip_subnet,p_ip_subnet, addr_count) && p->IfType==IF_TYPE_ETHERNET_CSMACD){
                    //the p_ip_subnet condition is pointless, because ip_in_any_subnet would return 0 if p_ip_subnet is NULL
                    //put it there because clang cries, though is pintless
                    for (int i = 0; i<addr_count; i++) {
                        if (p_ip_subnet[i].interface_type == IF_TYPE_IEEE80211) {
                            if (ips_share_subnet(p_ip_subnet[i],temp_ip_subnet)) p_ip_subnet[i] = temp_ip_subnet;
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
SOCKET_NODE *create_discv_sock_node() {
    char optval = 1;
    DWORD ttl = 1;
    SOCKET_NODE *node = (SOCKET_NODE *)malloc(sizeof(SOCKET_NODE));

    if (node == NULL) {
        perror("Failed to allocate memory for DISCV_SOCK");
        return NULL;
    }

    node->next = NULL;
    node->sock = WSASocketA(AF_INET, SOCK_DGRAM, IPPROTO_UDP,NULL,0,0x01);
    if (node->sock == INVALID_SOCKET) {
        perror("Failed to create socket");
        free(node);
        return NULL;
    }

    if (setsockopt(node->sock,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval)) != 0) {
        perror("setsockopt() SO_REUSEADDR failed");
        closesocket(node->sock);
        free(node);
        return NULL;
    }

    //set time to live to 1 --> local network, cant be routed
    if (setsockopt(node->sock,IPPROTO_IP,IP_MULTICAST_TTL,(const char *)&ttl,sizeof(ttl)) != 0) {
        perror("setsockopt() IP_MULTICAST_TTL failed");
        closesocket(node->sock);
        free(node);
        return NULL;
    }

    return node;
}

//____IP AND SUBNET HELPERS____//

uint32_t sub_mask_8to32b(const uint8_t mask_8b) {
    uint32_t mask_32b = 0;
    for (uint8_t j = 0; j < mask_8b; j++) {
        mask_32b |= 1;
        mask_32b <<= 1;
    }
    for (int i = 0; i < 32 - mask_8b-1; i++) {
        mask_32b <<= 1;
    }
    return mask_32b;
}

uint8_t ips_share_subnet(const IP_SUBNET addr1 , const IP_SUBNET addr2) {
    return (addr1.ip & addr1.mask) == (addr2.ip & addr2.mask);
}

uint8_t ip_in_any_subnet(const IP_SUBNET addr, const IP_SUBNET *p_addrs, const size_t num_addrs) {
    if (p_addrs == NULL) return 0;
    for (int i = 0; i < num_addrs; i++) {
        if (ips_share_subnet(addr, p_addrs[i])) return 1;
    }
    return 0;
}


//////////////////////////////////////////////////////
///                                                ///
///                  IO_FUNCTIONS                  ///
///                                                ///
//////////////////////////////////////////////////////

//todo: continue error handling from here

int send_discovery_packets(
    const int port,
    const uint32_t multicast_addr,
    SOCKET_LL *sockets,
    EFLAG *flag,
    const uint32_t pCount,
    const int32_t msec
    ) {
    //temporary variables for memory allocation
    SEND_INFO temp_info = {0}, *sInfo = NULL;
    size_t infolen = 0;
    void *temp;

    HANDLE *handles = NULL;
    size_t hCount = 0;

    int ret_val;
    DWORD wait_ret;
    uint32_t flag_val = 0;
    const int32_t temp_math = msec % 1000;

    struct timespec ts;

    PACKET packet;
    int routine_ret = 0;

    build_packet(&packet, MSG_INIT_PACKET, 0);

    while (1) {
        pthread_mutex_lock(&sockets->mutex);
        for (SOCKET_NODE *sock = sockets->head; sock != NULL; sock = sock->next){
            temp = calloc(1,sizeof(struct sockaddr_in));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.dest = temp;

            temp_info.dest->sin_family = AF_INET;
            temp_info.dest->sin_addr.S_un.S_addr = multicast_addr;
            temp_info.dest->sin_port = port;

            temp = malloc(sizeof(WSABUF));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.buf = temp;
            temp_info.buf->buf = NULL;

            temp = malloc(sizeof(PACKET));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.buf->buf = temp;
            memcpy(temp_info.buf->buf, &packet, sizeof(PACKET));
            temp_info.buf->len = sizeof(PACKET);

            temp = malloc(sizeof(OVERLAPPED));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.overlapped = temp;
            temp_info.overlapped->hEvent = WSACreateEvent();
            if (temp_info.overlapped->hEvent == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "WSACreateEvent() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }

            temp = malloc(sizeof(DWORD));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.bytes = temp;

            temp_info.socket = sock->sock;

            temp = realloc(sInfo, sizeof(SEND_INFO) * (infolen + 1));
            if (temp == NULL) {
                fprintf(stderr, "realloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            sInfo = temp;
            memcpy(sInfo + infolen, &temp_info, sizeof(SEND_INFO));
            infolen++;
            memset(&temp_info, 0, sizeof(SEND_INFO));//so that we dont double free

            flag_val = get_event_flag(flag);
            if (flag_val & EF_OVERRIDE_IO) {
                free_send_info(&temp_info);
                for (size_t i = 0; i < infolen; i++) {
                    free_send_info(&sInfo[i]);
                }
                free(handles);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                break;
            }
            if (flag_val & EF_TERMINATION) goto cleanup;

            ret_val = WSASendTo(sock->sock,
                sInfo[infolen - 1].buf,
                1,
                sInfo[infolen - 1].bytes,
                MSG_DONTROUTE,
                (struct sockaddr *)(sInfo[infolen - 1].dest),
                sizeof(struct sockaddr),
                sInfo[infolen - 1].overlapped,
                NULL);

            if (ret_val == SOCKET_ERROR) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n",WSAGetLastError());
                    pthread_mutex_unlock(&sockets->mutex);
                    routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                    goto cleanup;
                }
            }
        }
        pthread_mutex_unlock(&sockets->mutex);

        if (flag_val & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            for (size_t i = 0; i < infolen; i++) {
                free_send_info(&sInfo[i]);
            }
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
            continue;
        }

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (msec - temp_math)/1000;
        ts.tv_nsec += temp_math * 1000000;

        flag_val = get_event_flag(flag);
        if (flag_val & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            for (size_t i = 0; i < infolen; i++) {
                free_send_info(&sInfo[i]);
            }
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
            continue;
        }
        if (flag_val & EF_TERMINATION) goto cleanup;

        pthread_mutex_lock(&flag->mutex);
        pthread_cond_timedwait(&flag->cond, &flag->mutex, &ts);

        if (flag->event_flag & EF_TERMINATION) goto cleanup;
        if (flag->event_flag & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            for (size_t i = 0; i < infolen; i++) {
                free_send_info(&sInfo[i]);
            }
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
            continue;
        }

        pthread_mutex_unlock(&flag->mutex);

        if(create_handle_array_from_send_info(sInfo, infolen, &handles, &hCount)) {
            fprintf(stderr, "create_handle_array_from_send_info() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }

        wait_ret = WSAWaitForMultipleEvents(hCount,handles,TRUE,100, FALSE);
        if (wait_ret == WSA_WAIT_FAILED) {
            fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
            routine_ret = INDIGO_ERROR_WINLIB_ERROR ;
            goto cleanup;
        }
        if (wait_ret == WSA_WAIT_TIMEOUT) {
            for (size_t i = 0; i < hCount; i++) {
                wait_ret = WaitForSingleObject(handles[i], 0);
                if (wait_ret == WAIT_OBJECT_0) continue;

                if (wait_ret == WAIT_FAILED) {
                    fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                    goto cleanup;
                }

                if (wait_ret == WAIT_TIMEOUT) {
                    CancelIo(handles[i]);
                }
            }
        }

        if (sInfo == NULL) goto cleanup;

        for (size_t i = 0; i < pCount - 1; i++) {
            for (size_t j = 0; j < infolen; j++) {
                WSAResetEvent(handles[j]);
                ret_val = WSASendTo(sInfo[j].socket,
                sInfo->buf,
                1,
                sInfo->bytes,
                MSG_DONTROUTE,
                (struct sockaddr *)(sInfo->dest),
                sizeof(struct sockaddr),
                sInfo->overlapped,
                NULL);

                if (ret_val == SOCKET_ERROR) {
                    if (WSAGetLastError() != WSA_IO_PENDING) {
                        fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n",WSAGetLastError());
                        pthread_mutex_unlock(&sockets->mutex);

                        routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                        goto cleanup;
                    }
                }
            }

            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (msec - temp_math)/1000;
            ts.tv_nsec += temp_math * 1000000;

            flag_val = get_event_flag(flag);
            if (flag_val & EF_OVERRIDE_IO) {
                free_send_info(&temp_info);
                for (size_t l = 0; l < infolen; l++) {
                    free_send_info(&sInfo[l]);
                }
                free(handles);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                break;
            }
            if (flag_val & EF_TERMINATION) goto cleanup;

            pthread_mutex_lock(&flag->mutex);
            pthread_cond_timedwait(&flag->cond, &flag->mutex, &ts);

            if (flag->event_flag & EF_TERMINATION) goto cleanup;
            if (flag->event_flag & EF_OVERRIDE_IO) {
                free_send_info(&temp_info);
                for (size_t l = 0; l < infolen; l++) {
                    free_send_info(&sInfo[l]);
                }
                free(handles);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                break;
            }

            pthread_mutex_unlock(&flag->mutex);

            if(create_handle_array_from_send_info(sInfo, infolen, &handles, &hCount)) {
                fprintf(stderr, "create_handle_array_from_send_info() failed in send_discovery_packets()\n");
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }

            wait_ret = WSAWaitForMultipleEvents(hCount,handles,TRUE,100, FALSE);
            if (wait_ret == WSA_WAIT_FAILED) {
                fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                goto cleanup;
            }
            if (wait_ret == WSA_WAIT_TIMEOUT) {
                for (size_t k = 0; k < hCount; k++) {
                    wait_ret = WaitForSingleObject(handles[i], 0);
                    if (wait_ret == WAIT_OBJECT_0) continue;

                    if (wait_ret == WAIT_FAILED) {
                        fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                        routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                        goto cleanup;
                    }

                    if (wait_ret == WAIT_TIMEOUT) {
                        CancelIo(handles[k]);
                    }
                }
            }
        }
        if (flag_val & EF_OVERRIDE_IO) continue;


        free_send_info(&temp_info); // temporary
        for (size_t i = 0; i < infolen; i++) {
            free_send_info(&sInfo[i]);
        }
        free(handles);
        return 0;
    }
    cleanup:

    flag_val = get_event_flag(flag);
    if (flag_val & EF_TERMINATION) return -1;

    free_send_info(&temp_info);
    for (size_t i = 0; i < infolen; i++) {
        free_send_info(&sInfo[i]);
    }
    free(handles);
    return routine_ret;
}

int register_single_receiver(SOCKET sock, RECV_INFO **info, mempool_t* mempool) {
    RECV_INFO *temp_info;

    int recv_ret;


    if (*info == NULL) {
        if (allocate_recv_info(&temp_info, mempool)) {
            fprintf(stderr, "allocate_recv_info() failed in send_discovery_packets()\n");
            return 1;
        }

        temp_info->socket = sock;
        *(temp_info->flags) = 0;


        recv_ret = WSARecvFrom(sock,
            temp_info->buf,
            1,
            temp_info->bytes_recv,
            temp_info->flags,
            temp_info->source,
            temp_info->fromLen,
            temp_info->overlapped,
            NULL);

        if (recv_ret == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr,"WSARecvFrom() failed in register_single_discovery_receiver(): %d\n", WSAGetLastError());
                free_recv_info(temp_info, mempool);
                free(temp_info);
                return 1;
            }
        }
        *info = temp_info;
    }
    else {
        recv_ret = WSARecvFrom(sock,
            (*info)->buf,
            1,
            (*info)->bytes_recv,
            (*info)->flags,
            (*info)->source,
            (*info)->fromLen,
            (*info)->overlapped,
            NULL);

        if (recv_ret == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr,"WSARecvFrom() failed in register_single_discovery_receiver(): %d\n", WSAGetLastError());
                return 1;
            }
        }
    }

    return 0;
}

int register_multiple_receivers(SOCKET_LL *sockets, RECV_ARRAY *info, mempool_t* mempool, EFLAG *flag) {
    void *temp = NULL;
    RECV_INFO *tempinf = NULL;

    uint32_t flag_val = 0;

    int recv_ret;
    //in case we get an override flag we restart
    while (1) {
        flag_val = 0;

        info->head = NULL;
        info->size = 0;

        pthread_mutex_lock(&sockets->mutex);
        for (SOCKET_NODE *sock = sockets->head; sock != NULL; sock = sock->next) {
            temp = realloc(info->head, (info->size + 1) * sizeof(RECV_INFO));
            if (temp == NULL) {
                fprintf(stderr, "realloc() failed in register_multiple_discovery_receivers()\n");
                pthread_mutex_unlock(&sockets->mutex);
                return 1;
            }
            info->head = temp;

            if (allocate_recv_info_fields(info->head + info->size, mempool)) {
                fprintf(stderr, "allocate_recv_info_fields() failed in register_multiple_discovery_receivers()\n");
                temp = realloc(info->head, (info->size) * sizeof(RECV_INFO)); // we decrease the size by one
                if (temp == NULL) {
                    pthread_mutex_unlock(&sockets->mutex);
                    fprintf(stderr, "realloc() failed in register_multiple_discovery_receivers()\n");
                    return 1;
                }
                info->head = temp;
                pthread_mutex_unlock(&sockets->mutex);
                return 1;
            }

            tempinf = info->head + info->size;

            tempinf->socket = sock->sock;
            *(tempinf->flags) = 0;

            info->size++;

            flag_val = get_event_flag(flag);
            if (flag_val & EF_OVERRIDE_IO) {
                free_recv_array(info, mempool);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                break;
            }
            if (flag_val & EF_TERMINATION) {
                pthread_mutex_unlock(&sockets->mutex);
                return -1;
            }

            recv_ret = WSARecvFrom(sock->sock,
                tempinf->buf,
                1,
                tempinf->bytes_recv,
                tempinf->flags,
                tempinf->source,
                tempinf->fromLen,
                tempinf->overlapped,
                NULL);

            if (recv_ret == SOCKET_ERROR) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    fprintf(stderr,"WSARecvFrom() failed in register_multiple_discovery_receivers(): %d\n", WSAGetLastError());
                    pthread_mutex_unlock(&sockets->mutex);
                    return 1;
                }
            }
        }
        pthread_mutex_unlock(&sockets->mutex);
        if (flag_val & EF_OVERRIDE_IO) continue;
        return 0;
    }
}


int send_packet(int port, uint32_t addr, SOCKET socket, PACKET *packet, EFLAG *flag) {
    SEND_INFO temp_info;
    void *temp;
    int ret_val;
    DWORD wait_ret;
    uint32_t flag_val = 0;
    int routine_ret = 0;

    while (1) {
        temp = calloc(1,sizeof(struct sockaddr_in));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.dest = temp;

        temp_info.dest->sin_family = AF_INET;
        temp_info.dest->sin_addr.S_un.S_addr = addr;
        temp_info.dest->sin_port = port;

        temp = malloc(sizeof(WSABUF));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.buf = temp;
        temp_info.buf->buf = NULL;

        temp = malloc(sizeof(PACKET));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.buf->buf = temp;
        memcpy(temp_info.buf->buf, packet, sizeof(PACKET));
        temp_info.buf->len = sizeof(PACKET);

        temp = malloc(sizeof(OVERLAPPED));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.overlapped = temp;
        temp_info.overlapped->hEvent = WSACreateEvent();
        if (temp_info.overlapped->hEvent == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "WSACreateEvent() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }

        temp = malloc(sizeof(DWORD));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.bytes = temp;


        flag_val = get_event_flag(flag);
        if (flag_val & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
            break;
        }
        if (flag_val & EF_TERMINATION) goto cleanup;

        ret_val = WSASendTo(socket,
            temp_info.buf,
            1,
            temp_info.bytes,
            MSG_DONTROUTE,
            (struct sockaddr *)(temp_info.dest),
            sizeof(struct sockaddr),
            temp_info.overlapped,
            NULL);

        if (ret_val == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n",WSAGetLastError());
                routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                goto cleanup;
            }
        }

        if (flag_val & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
            continue;
        }


        wait_ret = WaitForSingleObject(temp_info.overlapped->hEvent, 100);
        if (wait_ret == WSA_WAIT_FAILED) {
            fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
            routine_ret = INDIGO_ERROR_WINLIB_ERROR ;
            goto cleanup;
        }
        if (wait_ret == WSA_WAIT_TIMEOUT) {
            wait_ret = WaitForSingleObject(temp_info.overlapped->hEvent, 150);
            if (wait_ret == WAIT_OBJECT_0) continue;

            if (wait_ret == WAIT_FAILED) {
                fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                goto cleanup;
            }

            if (wait_ret == WAIT_TIMEOUT) {
                CancelIo(temp_info.overlapped->hEvent);
            }
        }

        if (flag_val & EF_OVERRIDE_IO) continue;


        free_send_info(&temp_info);
        return 0;
    }
    cleanup:

    flag_val = get_event_flag(flag);
    if (flag_val & EF_TERMINATION) return -1;

    free_send_info(&temp_info);
    return routine_ret;
}


/////////////////////////////////////////////////////////////
///                                                       ///
///                  IO_HELPER_FUNCTIONS                  ///
///                                                       ///
/////////////////////////////////////////////////////////////

void build_packet(PACKET * restrict packet, const unsigned pac_type,const void * restrict data) {
    if (pac_type == MSG_INIT_PACKET) {
        memset(packet, 0, sizeof(PACKET));
        packet->magic_number = MAGIC_NUMBER;
        packet->pac_version = PAC_VERSION;
        packet->pac_type = pac_type;
        //todo: we will use the username
        if (gethostname(packet->data, PAC_DATA_BYTES) != 0 ) {
            strcpy(packet->data, "unknown_hostname");
        }
    }
    else{
        memset(packet, 0, sizeof(PACKET));
        packet->magic_number = MAGIC_NUMBER;
        packet->pac_version = PAC_VERSION;
        packet->pac_type = pac_type;
        if (!data) return;
        memcpy(packet->data, data, PAC_DATA_BYTES);
    }
}

int create_handle_array_from_send_info(const SEND_INFO *info, const size_t infolen, HANDLE **handles, size_t *hCount) {
    void *temp;
    if (info == NULL || handles == NULL || hCount == NULL) return 1;

    temp = malloc(infolen * sizeof(HANDLE));
    if (temp == NULL) {
        perror("Failed to allocate memory for send info");
        return 1;
    }
    *handles = temp;
    *hCount = infolen;

    for (size_t i = 0; i < infolen; i++) {
        (*handles)[i] = info[i].overlapped->hEvent;
    }

    return 0;
}

void free_send_info(const SEND_INFO *info) {
    if (info == NULL) return;

    free(info->dest);
    free(info->bytes);
    if (info->buf != NULL) {
        free(info->buf->buf);
        free(info->buf);
    }
    if (info->overlapped != NULL) {
        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
    }
}

int allocate_recv_info(RECV_INFO **info, mempool_t* mempool) {
    void *temp;

    if (info == NULL) return 1;

    *info = (RECV_INFO *)malloc(sizeof(RECV_INFO));
    if (*info == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        *info = NULL;
        return 1;
    }

    temp = malloc(sizeof (struct sockaddr));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->source = temp;

    temp = malloc(sizeof (int));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->fromLen = temp;
    *((*info)->fromLen) = sizeof(struct sockaddr);


    temp = malloc(sizeof (WSABUF));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free((*info)->fromLen);
        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->buf = temp;
    (*info)->buf->buf = NULL;

    temp = mempool->alloc(mempool);
    if (temp == NULL) {
        fprintf(stderr, "mempool alloc failed in allocate_recv_info()\n");

        free((*info)->buf);
        free((*info)->fromLen);
        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->buf->buf = temp;
    (*info)->buf->len = PAC_DATA_BYTES + sizeof(PACKET_INFO);

    temp = malloc(sizeof (OVERLAPPED));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        mempool->free(mempool,(*info)->buf->buf);
        free((*info)->buf);
        free((*info)->fromLen);
        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->overlapped = temp;
    (*info)->overlapped->hEvent = WSACreateEvent();
    if ((*info)->overlapped->hEvent == WSA_INVALID_EVENT) {
        fprintf(stderr, "WSACreateEvent failed in allocate_recv_info()\n");

        free((*info)->overlapped);
        mempool->free(mempool,(*info)->buf->buf);
        free((*info)->buf);
        free((*info)->fromLen);
        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }

    temp = malloc(sizeof (DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        WSACloseEvent((*info)->overlapped->hEvent);
        free((*info)->overlapped);
        mempool->free(mempool,(*info)->buf->buf);
        free((*info)->buf);
        free((*info)->fromLen);
        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->flags = temp;

    temp = malloc(sizeof (DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free((*info)->flags);
        WSACloseEvent((*info)->overlapped->hEvent);
        free((*info)->overlapped);
        mempool->free(mempool,(*info)->buf->buf);
        free((*info)->buf);
        free((*info)->fromLen);
        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->bytes_recv = temp;

    (*info)->socket = INVALID_SOCKET;

    return 0;
}

int allocate_recv_info_fields(RECV_INFO *info, mempool_t* mempool) {
    void *temp;

    if (info == NULL) return 1;

    temp = malloc(sizeof (struct sockaddr));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        return 1;
    }
    info->source = temp;

    temp = malloc(sizeof (int));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        free(info->source);
        return 1;
    }
    info->fromLen = temp;
    *(info->fromLen) = sizeof(struct sockaddr);

    temp = malloc(sizeof (WSABUF));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->fromLen);
        free(info->source);
        return 1;
    }
    info->buf = temp;
    info->buf->buf = NULL;

    temp = mempool->alloc(mempool);
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->buf->buf = temp;
    info->buf->len = PAC_DATA_BYTES + sizeof(PACKET_INFO);

    temp = malloc(sizeof (OVERLAPPED));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        mempool->free(mempool,info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->overlapped = temp;

    info->overlapped->hEvent = WSACreateEvent();
    if (info->overlapped->hEvent == WSA_INVALID_EVENT) {
        fprintf(stderr, "WSACreateEvent failed in allocate_recv_info()\n");

        free(info->overlapped);
        mempool->free(mempool,info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);
        return 1;
    }

    temp = malloc(sizeof (DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
        mempool->free(mempool,info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);
        return 1;
    }
    info->flags = temp;

    temp = malloc(sizeof (DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->flags);
        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
        mempool->free(mempool,info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->bytes_recv = temp;

    info->socket = INVALID_SOCKET;

    return 0;
}

void free_recv_info(const RECV_INFO *info, mempool_t* mempool) {
    if (info == NULL) return;


    if (info->buf) {
        mempool->free(mempool,info->buf->buf);
        free(info->buf);
    }
    if (info->overlapped) {
        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
    }

    free(info->fromLen);
    free(info->source);
    free(info->bytes_recv);
    free(info->flags);
}

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int *send_discovery_thread(SEND_ARGS *args) {
    uint32_t flag_val;
    struct timespec ts;
    int ret;
    int *process_return = NULL;

    //allocate memory for the return value
    process_return = malloc(sizeof(uint8_t));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;

    //send a packet burst when a device discovery operation starts
    ret = send_discovery_packets(args->port,args->multicast_addr,args->sockets,args->flag,3,150);
    if (ret > 0) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = ret;
        return process_return;
    }
    //returns -1 when we get an override excecution or
    if (ret == -1) {
        flag_val = get_event_flag(args->flag);
        if(flag_val & EF_TERMINATION){
            *process_return = 0;
            return process_return;
        }
    }

    //the main loop
    while (!termination_is_on(args->flag)) {
        ///////////////////////////////////
        ///  phase 1: check for events  ///
        ///////////////////////////////////

        flag_val = get_event_flag(args->flag);

        if (flag_val & EF_OVERRIDE_IO) {
            wait_on_flag_condition(args->flag, EF_OVERRIDE_IO, OFF);
        }

        else if (flag_val & EF_SEND_MULTIPLE_PACKETS) {

            reset_single_event(args->flag, EF_SEND_MULTIPLE_PACKETS);

            ret = send_discovery_packets(args->port,args->multicast_addr,args->sockets,args->flag,3,150);
            if (ret > 0) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                *process_return = ret;
                return process_return;
            }
            //returns -1 when we get an override excecution or termination event
            if (ret == -1) {
                flag_val = get_event_flag(args->flag);
                if(flag_val & EF_TERMINATION){
                    *process_return = 0;
                    return process_return;
                }
            }
        }//we don't care about other events, if they are there we shouldn't get them anyway


        ////////////////////////////////
        ///  phase 2: send a packet  ///
        ////////////////////////////////


        ret = send_discovery_packets(args->port,args->multicast_addr,args->sockets,args->flag,1,0);
        if (ret > 0) {
            set_event_flag(args->flag, EF_TERMINATION);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            *process_return = ret;
            return process_return;
        }
        //returns -1 when we get an override excecution or termination event
        if (ret == -1) {
            flag_val = get_event_flag(args->flag);
            if(flag_val & EF_TERMINATION){
                *process_return = 0;
                return process_return;
            }
        }

        /////////////////////////////////////////////////
        ///  phase 3: wait and check for termination  ///
        /////////////////////////////////////////////////

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += DISCOVERY_SEND_PERIOD_SEC;

        pthread_mutex_lock(&(args->flag->mutex));
        if (args->flag->event_flag & EF_TERMINATION) {
            free_event_flag(args->flag);
            free(args);
            *process_return = 0;
            break;
        }
        ret = 0;
        while ((ret == 0) && (!(args->flag->event_flag & EF_TERMINATION))) {
            ret = pthread_cond_timedwait(&(args->flag->cond), &(args->flag->mutex), &ts);

            if ((ret != ETIMEDOUT) && (ret != 0)) {
                fprintf(stderr, "pthread_cond_timedwait() failed in device_discovery_sending\n");
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                pthread_mutex_unlock(&(args->flag->mutex));
                *process_return = INDIGO_ERROR_INVALID_STATE;
                return process_return;
            }
            if (ret == 0) {
                if (args->flag->event_flag & EF_TERMINATION) {
                    pthread_mutex_unlock(&(args->flag->mutex));
                    *process_return = 0;
                    return process_return;
                }
            }
        }
        pthread_mutex_unlock(&(args->flag->mutex));
    }
    return process_return;
}

int *recv_discovery_thread(RECV_ARGS *args) {
    //todo we need a hash table to hold the expected packets
    RECV_ARRAY info = {0};
    RECV_INFO *recv_info = NULL;

    HANDLE *handles = NULL;
    size_t hCount;

    PACKET pack;
    PACKET_INFO *packet_info;

    uint32_t flag_val;
    DWORD wait_ret;
    int ret;

    IP_RATE_ARRAY *ip_rates = NULL;
    size_t rate_idx = 0;
    IP_SEND_RATE *ip_send_rate = NULL;


    time_t current_time = 0;

    int *process_return = NULL;

    //allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;

    //create the ip rate array
    ip_rates = ip_rate_array_new();
    if (ip_rates == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        return process_return;
    }


    //register all the sockets for receiving
    ret = register_multiple_receivers(args->sockets,&info,args->mempool, args->flag);
    if (ret > 0) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = ret;
        ip_rate_array_free(ip_rates);
        return process_return;
    }
    if (ret == -1) {
        flag_val = get_event_flag(args->flag);
        if(flag_val & EF_TERMINATION){
            *process_return = 0;
            ip_rate_array_free(ip_rates);
            return process_return;
        }
    }

    //create the handles array to wait for a packet
    ret = create_handle_array_from_recv_info(&info,&handles,&hCount);
    if (ret) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        free_recv_array(&info, args->mempool);
        *process_return = ret;
        ip_rate_array_free(ip_rates);
        return process_return;
    }

    handles[0] = args->termination_handle;
    handles[1] = args->wake_handle;

    while (!termination_is_on(args->flag)) {
        ///////////////////////////////////
        ///  phase 1: check for events  ///
        ///////////////////////////////////

        flag_val = get_event_flag(args->flag);

        if (flag_val & EF_OVERRIDE_IO) {
            free(handles);
            free_recv_array(&info, args->mempool);
            info.head = NULL;
            info.size = 0;
            hCount = 0;

            wait_on_flag_condition(args->flag, EF_OVERRIDE_IO, OFF);

            ret = register_multiple_receivers(args->sockets,&info, args->mempool, args->flag);
            if (ret > 0) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                *process_return = ret;
                ip_rate_array_free(ip_rates);
                return process_return;
            }

            if (ret == -1) {
                flag_val = get_event_flag(args->flag);
                if(flag_val & EF_TERMINATION){
                    *process_return = 0;
                    ip_rate_array_free(ip_rates);
                    return process_return;
                }
            }

            //create the handles array to wait for a packet
            ret = create_handle_array_from_recv_info(&info,&handles,&hCount);
            if (ret) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                free_recv_array(&info, args->mempool);
                *process_return = ret;
                ip_rate_array_free(ip_rates);
                return process_return;
            }

            handles[0] = args->termination_handle;
            handles[1] = args->wake_handle;
        }
        else if (flag_val & EF_TERMINATION) {
            free(handles);
            free_recv_array(&info, args->mempool);
            *process_return = 0;
            ip_rate_array_free(ip_rates);
            return process_return;
        }

        ////////////////////////////////////
        ///  phase 2: wait for a packet  ///
        ////////////////////////////////////

        //todo limit the maximum handles to WSA_MAXIMUM_WAIT_EVENTS (64)
        //todo set a long timeout, to prevent deadlock (idk windows says something like that)

        wait_ret = WSAWaitForMultipleEvents(hCount, handles,FALSE,WSA_INFINITE,FALSE);

        /////////////////////////////////////
        ///  phase 3: process the packet  ///
        /////////////////////////////////////

        if (wait_ret == WSA_WAIT_FAILED) {
            fprintf(stderr, "WSAWaitForMultipleEvents() failed in recv_discovery_thread: %d\n", WSAGetLastError());
            set_event_flag(args->flag, EF_TERMINATION);
            set_event_flag(args->wake, EF_WAKE_MANAGER);

            free(handles);
            free_recv_array(&info, args->mempool);

            *process_return = 1;
            ip_rate_array_free(ip_rates);
            return process_return;
        }

        wait_ret -= WSA_WAIT_EVENT_0;

        //the termination handle is signaled
        if (wait_ret == 0) {
            free(handles);
            free_recv_array(&info, args->mempool);

            *process_return = 0;
            ip_rate_array_free(ip_rates);
            return process_return;
        }

        //the wake handle is signaled
        if (wait_ret == 1) {
            WSAResetEvent(handles[1]);
            continue;
        } // we got a wake event so we continue

//check the handles one by one
        for (size_t i = wait_ret; i < hCount; i++) {
            //check is the event is signaled
            wait_ret = WaitForSingleObject(handles[i],0);

            if (wait_ret == WAIT_FAILED) {
                printf("WaitForSingleObject() failed in recv_discovery_thread: %d\n", WSAGetLastError());
                fflush(stdout);
                free(handles);
                free_recv_array(&info, args->mempool);

                *process_return = 0;
                ip_rate_array_free(ip_rates);
                return process_return;
            }

            if (wait_ret == WAIT_OBJECT_0){
                //we received on that socket
                recv_info = (info.head) + i - 2;

                //check the packet we received

                if ((*(recv_info->bytes_recv) > sizeof(PACKET)) || (*(recv_info->bytes_recv) < PAC_MIN_BYTES)){
                    WSAResetEvent(handles[i]);
                    if (register_single_receiver(recv_info->socket,&recv_info, args->mempool)) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free_recv_array(&info, args->mempool);
                        free(handles);
                        ip_rate_array_free(ip_rates);
                        return process_return;
                    }
                    continue;
                }

                /*todo: when blocking an ip make sure you block the ip on that network
                        todo: if the system is connected on more than 1 network then banning one ip,
                        todo: the ban applies on the origin network
                        todo: you can do that by blocking the ip on that socket*/

                //here we just check if the ip is banned, we do not evaluate if it should be banned
                if(ip_rate_search(
                    ip_rates, ((struct sockaddr_in *)(recv_info->source))->sin_addr.S_un.S_addr, &rate_idx)) {

                    ip_rate_get(ip_rates, rate_idx, &ip_send_rate);
                    if (ip_send_rate->state == INDIGO_IP_STATE_SOFT_BANNED){
                        if (time(NULL) > ip_send_rate->ignore_until) {
                            ip_send_rate->ignore_until = 0;
                            ip_send_rate->state = INDIGO_IP_STATE_DEFAULT;
                        }
                    }
                }
                if (ip_send_rate->state != INDIGO_IP_STATE_DEFAULT) {
                    if (register_single_receiver(recv_info->socket,&recv_info, args->mempool)) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free_recv_array(&info, args->mempool);
                        free(handles);
                        ip_rate_array_free(ip_rates);
                        return process_return;
                    }
                    continue;
                }

                //everything we need to know is in the first 6 bytes, the rest is redundant
                memcpy(&pack,recv_info->buf->buf,6);

                //check the magic number (not an absolut way to check if a packet is for us but will prolly work)
                if (pack.magic_number != MAGIC_NUMBER){
                    WSAResetEvent(handles[i]);
                    if (register_single_receiver(recv_info->socket,&recv_info, args->mempool)) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free_recv_array(&info, args->mempool);
                        free(handles);
                        ip_rate_array_free(ip_rates);
                        return process_return;
                    }
                    continue;
                }

                //impose a ban if needed (to avoid ddos)
                //update expected packets
                switch (pack.pac_type) {
                    case MSG_INIT_PACKET:
                        current_time = time(NULL);
                    //todo impose 100ms interval, and soft ban for 10s
                        ip_send_rate->last_dis_packet = current_time;
                        break;
                    case MSG_SIGNING_REQUEST:
                        current_time = time(NULL);
                        if (current_time - ip_send_rate->last_request > SIGNATURE_REQUEST_MAX_PER_IP_INTERVAL) {
                            ip_send_rate->state = INDIGO_IP_STATE_HARD_BANNED;
                        }
                        ip_send_rate->last_request = current_time;
                        break;
                    default:
                        break;
                }
                if (ip_send_rate->state != INDIGO_IP_STATE_DEFAULT) {
                    if (register_single_receiver(recv_info->socket,&recv_info, args->mempool)) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free_recv_array(&info, args->mempool);
                        free(handles);
                        ip_rate_array_free(ip_rates);
                        return process_return;
                    }
                    continue;
                }

                //we need to push the pointer to the received data (recv_info->buf->buf)

                //push the packet to be processed
                //the buffer has enough space for the packet and metadata (packet_info)
                //(its like a struct, but it's not),
                //I've agreed that we don't need a struct, and I will mess up like real fag

                //here we put the packet info at the end of the buffer that we received (there is enough space)
                packet_info = (void *)recv_info->buf->buf + sizeof(PACKET);
                packet_info->packet = recv_info->buf->buf;
                packet_info->address = *((struct sockaddr_in *)recv_info->source);
                packet_info->socket = recv_info->socket;
                packet_info->timestamp = time(NULL);


                if (queue_push(args->queue,recv_info->buf->buf,QET_NEW_PACKET)) {
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    free_recv_array(&info, args->mempool);
                    free(handles);
                    ip_rate_array_free(ip_rates);
                    return process_return;
                }
                set_event_flag(args->flag, EF_NEW_PACKET);
                set_event_flag(args->wake, EF_WAKE_MANAGER);

                //reset and re-receive
                WSAResetEvent(handles[i]);

                //we need to allocate a new buffer for receiving from the pool
                recv_info->buf->buf = args->mempool->alloc(args->mempool);
                if (recv_info->buf->buf == NULL) {
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    free_recv_array(&info, args->mempool);
                    free(handles);
                    ip_rate_array_free(ip_rates);
                    return process_return;
                }

                if (register_single_receiver(recv_info->socket,&recv_info, args->mempool)) {
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_WINLIB_ERROR;
                    free_recv_array(&info, args->mempool);
                    free(handles);
                    ip_rate_array_free(ip_rates);
                    return process_return;
                }
            }
        }
    }
    free(handles);
    free_recv_array(&info, args->mempool);
    ip_rate_array_free(ip_rates);
    *process_return = 0;
    return process_return;
}

//todo: re-write the packet handler, we need to handle every type of packet
int *packet_handler_thread(PACKET_HANDLER_ARGS *args) {
    uint32_t flag_val = 0;
    QNODE *node;

    void *mac_address = NULL;
    ULONG mac_address_len = 0;
    PULONG p_mac_address_len = &mac_address_len;

    time_t curr_time;
    struct timespec ts;
    time_t lowest_time = 0, time_diff;

    unsigned char iterations_until_cleanup = 10;

    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char signed_nonce[crypto_sign_BYTES + INDIGO_NONCE_SIZE];


    PACKET_NODE *temp_dev, *found_dev;
    PACKET_INFO* packet_info;
    PACKET *packet;
    PACKET_HEADER packet_header;

    int ret = 0; //general purpose return variable


    int *process_return = NULL;

    //allocate memory for the return value
    process_return = malloc(sizeof(uint8_t));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;

    //the main loop
    while (!termination_is_on(args->flag)) {
        ///////////////////////////////////
        ///  phase 1: check for events  ///
        ///////////////////////////////////

        flag_val = get_event_flag(args->flag);
        if (flag_val & EF_TERMINATION) {
            break;
        }
        if (flag_val & EF_NEW_PACKET) {
            reset_single_event(args->flag, EF_NEW_PACKET);

            node = queue_pop(args->queue,QOPT_NON_BLOCK);

            if (node == NULL) continue;

            if (node->type != QET_NEW_PACKET) {
                //probably an error but good to check
                destroy_qnode(node);
                continue;
            }

            packet = node->data;
            packet_info = node->data + sizeof(PACKET);

            destroy_qnode(node);

            memcpy(&packet_header, packet, sizeof(packet_header));

            //todo handle all types of packets
            switch (packet_header.pac_type) {
                case MSG_INIT_PACKET:
                    mac_address_len = 6;
                    mac_address = calloc(1, mac_address_len);
                    if (mac_address == NULL) {
                        fprintf(stderr, "malloc() failed in device_discovery_receiving\n");
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        return process_return;
                    }

                    if (SendARP(packet_info->address.sin_addr.S_un.S_addr,INADDR_ANY, mac_address, p_mac_address_len)
                        != NO_ERROR) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free(mac_address);
                        return process_return;
                        }

                    memcpy(packet_info->mac_address, mac_address, mac_address_len);
                    packet_info->mac_address_len = mac_address_len;

                    free(mac_address);

                    pthread_mutex_lock(&(args->devices->mutex));

                    found_dev = device_exists(args->devices, packet_info);
                    if (found_dev != NULL) {
                        found_dev->packet.timestamp = time(NULL); //renew the timestamp
                        pthread_mutex_unlock(&args->devices->mutex);
                        continue;
                    }

                    temp_dev = malloc(sizeof(PACKET_NODE));
                    if (temp_dev == NULL) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        return process_return;
                    }
                    memcpy(&(temp_dev->packet), &packet_info, sizeof(PACKET_INFO));

                    temp_dev->next = args->devices->head;
                    args->devices->head = temp_dev;

                    pthread_mutex_unlock(&(args->devices->mutex));

                    //send signing request
                    randombytes_buf(nonce,INDIGO_NONCE_SIZE);
                    build_packet(packet,MSG_SIGNING_REQUEST,nonce);
                    send_packet((int)htonl(PORT),temp_dev->packet.address.sin_addr.S_un.S_addr,
                        temp_dev->packet.socket,packet, args->flag);
                    //todo: add a singing expected packet to the list

                    break;
                case MSG_SIGNING_REQUEST:
                    //sign the nonce and send the signature with the public key and a new nonce
                    if (sign_buffer(args->signing_keys, packet->data, INDIGO_NONCE_SIZE,signed_nonce,NULL)) {
                        //IDK do something
                        continue;
                    }
                    build_packet(packet, MSG_SIGNING_RESPONSE, NULL);

                    memcpy(packet->data, signed_nonce, sizeof(signed_nonce));

                    sodium_mprotect_readonly(args->signing_keys);
                    memcpy(packet->data + sizeof(signed_nonce), args->signing_keys->public
                        , sizeof(args->signing_keys->public));
                    sodium_mprotect_noaccess(args->signing_keys);

                    randombytes_buf(nonce,INDIGO_NONCE_SIZE);
                    memcpy(packet->data + sizeof(signed_nonce) + crypto_sign_PUBLICKEYBYTES,nonce
                        , INDIGO_NONCE_SIZE);
                //todo set the an expected packet, keep the nonce we sent
                //todo: make sure all override flags are risen in the thread_manager
                    send_packet((int)htonl(PORT),packet_info->address.sin_addr.S_un.S_addr,packet_info->socket
                        ,packet,args->flag);
                    break;
                case MSG_SIGNING_RESPONSE:
                    //todo: verify the signature and store the public key to the device node

                    ret = crypto_sign_open(nonce,NULL, packet->data, INDIGO_NONCE_SIZE + crypto_sign_BYTES
                    ,(unsigned char *)(packet->data + sizeof(signed_nonce) + crypto_sign_PUBLICKEYBYTES));
                    if (ret) {
                        //todo: mark this device to be blocked, or just ghost, or send error message
                    }

                    //todo check the nonce with the nonce we sent to be signed and then proceed
                    //todo better send error message, track the failed attempts and then ban

                    //todo if we haven't verified this device send a signing request
                case MSG_RESEND:
                case MSG_FILE_CHUNK:
                case MSG_STOP_FILE_TRANSMISSION:
                case MSG_PAUSE_FILE_TRANSMISSION:
                case MSG_CONTINUE_FILE_TRANSMISSION:
                case MSG_ERR:
                default:
                    break;
            }

            //we no longer need the packet
            args->mempool->free(args->mempool,packet);
            packet = NULL;
            packet_info = NULL;

            //here if there are more packets in the queue we go back up to process them,
            //but we don't want to have ghost devises,
            //so in case there are too many packets we refresh the list once per 10 packets processed
            if (iterations_until_cleanup > 0) {
                iterations_until_cleanup--;
                if (!queue_is_empty(args->queue)) continue;
            }
            else iterations_until_cleanup = 10;

            /////////////////////////////////////////
            ///  phase 2: update the device list  ///
            /////////////////////////////////////////

            curr_time = time(NULL);

            pthread_mutex_lock(&(args->devices->mutex));
            lowest_time = curr_time - args->devices->head->packet.timestamp;
            for (PACKET_NODE *temp = args->devices->head; temp != NULL; temp = temp->next) {
                time_diff = curr_time - temp->packet.timestamp;
                if (time_diff > DEVICE_TIME_UNTIL_DISCONNECTED)
                    remove_device(args->devices,&(temp->packet));
                if (time_diff < lowest_time) lowest_time = time_diff;
            }
            pthread_mutex_unlock(&(args->devices->mutex));

            //there is no need to sleep if there is more stuff to do
            if (!queue_is_empty(args->queue)) continue;

            /////////////////////////////////////////////
            ///  phase 3: wait a little and go again  ///
            /////////////////////////////////////////////
            clock_gettime(CLOCK_REALTIME,&ts);
            ts.tv_sec +=lowest_time;

            pthread_mutex_lock(&args->flag->mutex);
            pthread_cond_timedwait(&args->flag->cond,&args->flag->mutex,&ts);
            pthread_mutex_unlock(&args->flag->mutex);

        }
    }
        return process_return;
}

int *interface_updater_thread(INTERFACE_UPDATE_ARGS* args) {
   HANDLE notification_handle = NULL;
    HANDLE handles[2];
    WSAOVERLAPPED overlapped = {0};
    DWORD retVal;
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

    //initialize the array of handles
    handles[0] = args->termination_handle;
    handles[1] = overlapped.hEvent;


    //register for address changes
    retVal = NotifyAddrChange(&notification_handle,&overlapped);
    if (retVal != ERROR_IO_PENDING) {
        fprintf(stderr, "NotifyAddrChange() failed in interface_updater\n");
        //print what the fuzz is about
        switch (retVal) {
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

    //the main loop
    while (!termination_is_on(args->flag)) {
        //the function blocks here and waits for an event
        printf("DEBUG: entered waiting\n");
        fflush(stdout);
        retVal = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        printf("DEBUG: exited waiting\n");
        fflush(stdout);
        //error check
        if (retVal == WAIT_FAILED) {
            //
            perror("WaitForMultipleObjects() failed in interface_updater");
            *process_return = INDIGO_ERROR_WINLIB_ERROR;
            set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            printf("DEBUG: update exit\n");
            fflush(stdout);
            return process_return;
        }
        //check which event was signalled
        if (retVal - WAIT_OBJECT_0 == 1) {
            //interface update
            printf("DEBUG: interface update\n");
            fflush(stdout);

            set_event_flag(args->flag, EF_INTERFACE_UPDATE | EF_OVERRIDE_IO);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            WSAResetEvent(overlapped.hEvent);

            pthread_mutex_lock(&(args->sockets->mutex));
            free_discv_sock_ll(args->sockets->head);
            args->sockets->head = get_discovery_sockets(args->port, args->multicast_addr);
            if (args->sockets->head == NULL) {
                //no discovery sockets, no device discovery
                set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                *process_return = INDIGO_ERROR_NO_ADDRESS_FOUND;
                pthread_mutex_unlock(&(args->sockets->mutex));
                printf("DEBUG: update exit\n");
                fflush(stdout);
                return process_return;
            }
            pthread_mutex_unlock(&(args->sockets->mutex));
            reset_single_event(args->flag, EF_OVERRIDE_IO);

            //re-register for address changes
            retVal = NotifyAddrChange(&notification_handle,&overlapped);
            if (retVal != ERROR_IO_PENDING) {
                fprintf(stderr, "NotifyAddrChange() failed in interface_updater\n");
                //print what the fuzz is about
                switch (retVal) {
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
        else if (retVal - WAIT_OBJECT_0 == 0) {
            //termination event
            CancelIPChangeNotify(&overlapped);
            printf("DEBUG: update exit\n");
            fflush(stdout);
            return process_return;
        }
        else {
            //there is probably an error
            fprintf(stderr, "WaitForMultipleObjects() failed in interface_updater: %d\n",WSAGetLastError());

            set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            CancelIPChangeNotify(&overlapped);
            *process_return = INDIGO_ERROR_INVALID_STATE;
            printf("DEBUG: update exit\n");
            fflush(stdout);
            return process_return;
        }
    }
    //termination event signalled and loop ended
    printf("DEBUG: update exit\n");
    fflush(stdout);

    CancelIPChangeNotify(&overlapped);
    return process_return;
}

int *thread_manager_thread(MANAGER_ARGS *args) {
    //for the thread creation
    pthread_t tid_send = pthread_self(),
    tid_receive = pthread_self(),
    tid_update = pthread_self(),
    tid_handler = pthread_self();

    int *send_ret = NULL, *receive_ret = NULL, *update_ret = NULL, *handler_ret = NULL;

    QUEUE *packet_queue = NULL;

    mempool_t *mempool = NULL; //the pool used for receiving
    mempool_attr pool_attr;

    //the thread args
    SEND_ARGS *send_args = NULL;
    RECV_ARGS *recv_args = NULL;
    INTERFACE_UPDATE_ARGS *update_args = NULL;
    PACKET_HANDLER_ARGS *handler_args = NULL;

    //for the event handling
    QNODE *qnode_pop = NULL;

    //the discovery sockets list
    SOCKET_LL *sockets;

    //flags
    uint32_t flag_val;

    void *temp = NULL;

    int *process_return = NULL;

/*_________________________________________HERE STARTS THE FUNCTIONS LOGIC____________________________________________*/
    //allocate memory for the return value
    process_return = malloc(sizeof(uint8_t));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        free(args);
        return NULL;
    }
    *process_return = 0;

    //prepare to create the threads

    //create the sockets
    sockets = malloc(sizeof(SOCKET_LL));
    if (sockets == NULL) {
        fprintf(stderr, "malloc() failed in discovery_manager_thread\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    pthread_mutex_init(&sockets->mutex, NULL);
    pthread_cond_init(&sockets->cond, NULL);
    sockets->head = NULL;

    temp = get_discovery_sockets(args->port, args->multicast_addr);
    if (temp == NULL) {
        fprintf(stderr, "Error in get_discovery_sockets\n");
        goto cleanup;
    }
    sockets->head = temp;

    //create the packet queue
    packet_queue = (QUEUE *)malloc(sizeof(QUEUE));
    if (packet_queue == NULL) {
        fprintf(stderr, "Failed to allocate memory for queue_receiving\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    if (init_queue(packet_queue)) {
        fprintf(stderr, "init_queue failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //create the memory pool
    pool_attr.dynamic_pool = 1;
    pool_attr.growth_factor = 1;
    //the initial mempool is about 1MiB, it may be extended automatically if needed
    mempool = new_mempool(1<<10, sizeof(PACKET) + sizeof(PACKET_INFO), &pool_attr);
    if (!mempool) {
        fprintf(stderr, "Failed to create mempool\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //create threads
    if (create_interface_updater_thread(&update_args,args->port, args->multicast_addr, args->flag, sockets, &tid_update)) {
        fprintf(stderr, "create_interface_updater_thread failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    if (create_packet_handler_thread(&handler_args, args->flag, packet_queue, mempool, args->devices, args->master_key, &tid_handler)) {
        fprintf(stderr, "create_packet_handler_thread failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    if (create_receiving_thread(&recv_args, sockets, packet_queue, mempool, args->flag, &tid_receive)) {
        fprintf(stderr, "create_discovery_receiving_thread failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    if (create_discovery_sending_thread(&send_args, args->port, args->multicast_addr, sockets, args->flag, &tid_send)) {
        fprintf(stderr, "create_discovery_sending_thread failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //the main loop
    while (!termination_is_on(args->flag)) {
        pthread_mutex_lock(&args->flag->mutex);
        pthread_cond_wait(&args->flag->cond, &args->flag->mutex);
        flag_val = args->flag->event_flag;
        pthread_mutex_unlock(&args->flag->mutex);

        if (termination_is_on(args->flag)) {
            *process_return = 0;
            break;
        }

        if (!(flag_val & EF_WAKE_MANAGER)) continue;

        //check the thread flags

        //check the sending thread
        flag_val = get_event_flag(send_args->flag);
        if (flag_val & EF_TERMINATION) {
            //for now, we terminate the whole operation, later we may pause or continue as we are
            goto cleanup;
        }

        //check the receiving thread
        flag_val = get_event_flag(recv_args->flag);
        if (flag_val & EF_TERMINATION) {
            //for now, we terminate the whole operation, later we may pause or continue as we are
            goto cleanup;
        }
        //todo remove since the packet handler communicates directly with the receiver
        //in this case we just forward to the packet handler
        if (flag_val & EF_NEW_PACKET) {
            qnode_pop = queue_pop(packet_queue, QOPT_NON_BLOCK);
            if (qnode_pop != NULL) {
                if (queue_push(packet_queue,qnode_pop->data,qnode_pop->type)) {
                    destroy_qnode(qnode_pop);
                    goto cleanup;
                }
                destroy_qnode(qnode_pop);
                update_event_flag(handler_args->flag, EF_NEW_PACKET);
            }
        }

        //check the interface updater thread
        flag_val = get_event_flag(update_args->flag);
        if (flag_val & EF_TERMINATION) {
            //for now, we terminate the whole operation, later we may pause or continue as we are
            goto cleanup;
        }
        if (flag_val & EF_INTERFACE_UPDATE) {
            printf("DEBUG: manager override\n");
            fflush(stdout);

            reset_single_event(update_args->flag, EF_INTERFACE_UPDATE);
            if (flag_val & EF_OVERRIDE_IO) {
                update_event_flag(send_args->flag, EF_OVERRIDE_IO);
                update_event_flag(recv_args->flag, EF_OVERRIDE_IO);

                wait_on_flag_condition(update_args->flag, EF_OVERRIDE_IO, OFF);

                reset_single_event(send_args->flag, EF_OVERRIDE_IO);
                reset_single_event(recv_args->flag, EF_OVERRIDE_IO);
            }
            printf("DEBUG: override complete\n");
            fflush(stdout);
        }

        //check the packet handler thread
        flag_val = get_event_flag(handler_args->flag);
        if (flag_val & EF_TERMINATION) {
            //for now, we terminate the whole operation, later we may pause or continue as we are
            goto cleanup;
        }
    }

    WSASetEvent(recv_args->termination_handle);
    WSASetEvent(update_args->termination_handle);

    set_event_flag(send_args->flag, EF_TERMINATION);
    set_event_flag(recv_args->flag, EF_TERMINATION);
    set_event_flag(handler_args->flag, EF_TERMINATION);
    set_event_flag(update_args->flag, EF_TERMINATION);

    if (pthread_equal(tid_send, pthread_self()) == 0) pthread_join(tid_send, (void **)&send_ret);
    if (pthread_equal(tid_receive, pthread_self()) == 0) pthread_join(tid_receive, (void **)&receive_ret);
    if (pthread_equal(tid_handler, pthread_self()) == 0) pthread_join(tid_handler, (void **)&handler_ret);
    if (pthread_equal(tid_update, pthread_self()) == 0) pthread_join(tid_update, (void **)&update_ret);

    free(send_ret);
    free(receive_ret);
    free(update_ret);
    free(handler_ret);


    //send args
    free_event_flag(send_args->flag);
    free(send_args);

    //receive args
    WSACloseEvent(recv_args->termination_handle);
    WSACloseEvent(recv_args->wake_handle);
    free_event_flag(recv_args->flag);
    free(recv_args);

    //update args
    WSACloseEvent(update_args->termination_handle);
    free_event_flag(update_args->flag);
    free(update_args);

    //handler args
    free_event_flag(handler_args->flag);
    free(handler_args);

    pthread_mutex_destroy(&sockets->mutex);
    pthread_cond_destroy(&sockets->cond);
    free_discv_sock_ll(sockets->head);

    destroy_queue(packet_queue);

    free_mempool(mempool);

    free(packet_queue);

    free_event_flag(args->flag);
    free(args);

    printf("DEBUG: manager thread exit\n");
    fflush(stdout);

    return process_return;

    cleanup:
    //signal termination to all threads
    if (recv_args != NULL) {
        WSASetEvent(recv_args->termination_handle);
    }
    if (update_args != NULL) {
        WSASetEvent(update_args->termination_handle);
    }

    if (send_args != NULL) set_event_flag(send_args->flag, EF_TERMINATION);
    if(recv_args != NULL)set_event_flag(recv_args->flag, EF_TERMINATION);
    if (handler_args != NULL) set_event_flag(handler_args->flag, EF_TERMINATION);
    if (update_args != NULL) set_event_flag(update_args->flag, EF_TERMINATION);

    //wait for the threads to terminate before we deallocate any resources
    if (pthread_equal(tid_send, pthread_self()) == 0) pthread_join(tid_send, (void **)&send_ret);
    if (pthread_equal(tid_receive, pthread_self()) == 0) pthread_join(tid_receive, (void **)&receive_ret);
    if (pthread_equal(tid_update, pthread_self()) == 0) pthread_join(tid_update, (void **)&update_ret);
    if (pthread_equal(tid_handler, pthread_self()) == 0) pthread_join(tid_handler, (void **)&handler_ret);

    free(send_ret);
    free(receive_ret);
    free(update_ret);
    free(handler_ret);

    //free the args of the threads
    //send
    if (pthread_equal(tid_send, pthread_self()) == 0) {
        free(send_args->flag);
        free(send_args);
    }
    //receive
    if (pthread_equal(tid_receive, pthread_self()) == 0) {
        WSACloseEvent(recv_args->termination_handle);
        WSACloseEvent(recv_args->wake_handle);
        free_event_flag(recv_args->flag);
        free(recv_args);
    }
    //updater
    if (pthread_equal(tid_update, pthread_self()) == 0) {
        WSACloseEvent(update_args->termination_handle);
        free_event_flag(update_args->flag);
        free(update_args);
    }
    //packet handler
    if (pthread_equal(tid_handler, pthread_self()) == 0) {
        free_event_flag(handler_args->flag);
        free(handler_args);
    }

    pthread_mutex_destroy(&sockets->mutex);
    pthread_cond_destroy(&sockets->cond);
    free_discv_sock_ll(sockets->head);

    destroy_queue(packet_queue);
    free(packet_queue);

    free(mempool);

    free_event_flag(args->flag);
    free(args);

    printf("DEBUG: manager thread exit\n");
    fflush(stdout);
    return process_return;

}


///////////////////////////////////////////////////////////////////
///                                                             ///
///                  THREAD_CREATING_FUNCTIONS                  ///
///                                                             ///
///////////////////////////////////////////////////////////////////


int cancel_device_discovery(pthread_t tid, EFLAG *flag) {
    int *ret = NULL, val;

    set_event_flag(flag, EF_TERMINATION | EF_WAKE_MANAGER);

    if (pthread_equal(tid,pthread_self()) == 0) {
        pthread_join(tid,(void **)&ret);
    }
    printf("DEBUG: manager thread joined\n");
    fflush(stdout);

    if (ret == NULL) return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    val = *ret;
    free(ret);
    return val;
}

int create_thread_manager_thread(MANAGER_ARGS **args, int port, uint32_t multicast_address, PACKET_LIST *devices, pthread_t *tid){
    pthread_t thread;

    MANAGER_ARGS *manager_args = malloc(sizeof(MANAGER_ARGS));
    if (manager_args == NULL) {
        fprintf(stderr, "Error allocating memory for MANAGER_ARGS\n");
        return 1;
    }
    *args = manager_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_discovery_sending_thread\n");
        free(manager_args);
        return 1;
    }

    manager_args->flag = flag;
    manager_args->port = port;
    manager_args->multicast_addr = multicast_address;
    manager_args->devices = devices;

    if (pthread_create(&thread, NULL, (void *)(&thread_manager_thread), manager_args)) {
        free_event_flag(flag);
        free(*args);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_discovery_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, SOCKET_LL *sockets, EFLAG *wake_mngr, pthread_t *tid){
    pthread_t thread;

    SEND_ARGS *send_args = malloc(sizeof(SEND_ARGS));
    if (send_args == NULL) {
        fprintf(stderr, "malloc() failed in create_discovery_sending_thread\n");
        return 1;
    }
    *args = send_args;


    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_discovery_sending_thread\n");
        free(send_args);
        return 1;
    }

    send_args->port = port;
    send_args->multicast_addr = multicast_address;
    send_args->sockets = sockets;
    send_args->wake = wake_mngr;
    send_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&send_discovery_thread), send_args)) {
        free_event_flag(flag);
        free(args);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_receiving_thread(
    RECV_ARGS **args, SOCKET_LL *sockets, QUEUE *queue, mempool_t* mempool, EFLAG *wake_mngr, pthread_t *tid){

    pthread_t thread;

    RECV_ARGS *recv_args = malloc(sizeof(RECV_ARGS));
    if (recv_args == NULL) {
        fprintf(stderr, "malloc() failed in create_discovery_sending_thread\n");
        return 1;
    }
    *args = recv_args;


    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_discovery_sending_thread\n");
        free(recv_args);
        return 1;
    }


    recv_args->wake_handle = WSACreateEvent();
    if (recv_args->wake_handle == NULL) {
        fprintf(stderr, "WSACreateEvent() failed in create_discovery_sending_thread\n");
        free_event_flag(flag);
        free(recv_args);
        return 1;
    }

    recv_args->termination_handle = WSACreateEvent();
    if (recv_args->termination_handle == NULL) {
        fprintf(stderr, "WSACreateEvent() failed in create_discovery_receiving_thread\n");
        free_event_flag(flag);
        WSACloseEvent(recv_args->wake_handle);
        free(recv_args);
    }

    recv_args->queue = queue;
    recv_args->mempool = mempool;
    recv_args->sockets = sockets;
    recv_args->wake = wake_mngr;
    recv_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&recv_discovery_thread), recv_args)) {
        free_event_flag(flag);
        free(recv_args);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_interface_updater_thread(INTERFACE_UPDATE_ARGS **args, int port, uint32_t multicast_address, EFLAG *wake_mngr, SOCKET_LL *sockets, pthread_t *tid){
    pthread_t thread;

    INTERFACE_UPDATE_ARGS *update_args = malloc(sizeof(INTERFACE_UPDATE_ARGS));
    if (update_args == NULL) {
        fprintf(stderr, "malloc() failed in create_interface_updater_thread\n");
        return 1;
    }
    *args = update_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_interface_updater_thread\n");
        free(update_args);
        return 1;
    }

    update_args->termination_handle = WSACreateEvent();
    if (update_args->termination_handle == NULL) {
        fprintf(stderr, "WSACreateEvent() failed in create_interface_updater_thread\n");
        free_event_flag(flag);
        free(update_args);
        return 1;
    }

    update_args->port = port;
    update_args->multicast_addr = multicast_address;
    update_args->sockets = sockets;
    update_args->wake = wake_mngr;
    update_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&interface_updater_thread), update_args)) {
        free_event_flag(flag);
        free(update_args);
        return 1;
    }

    *tid = thread;
    return 0;
}

int create_packet_handler_thread(
    PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *queue, mempool_t* mempool, PACKET_LIST *dev_list, void*
    master_key, pthread_t *tid){

    pthread_t thread;

    PACKET_HANDLER_ARGS *handler_args = malloc(sizeof(INTERFACE_UPDATE_ARGS));
    if (handler_args == NULL) {
        fprintf(stderr, "malloc() failed in create_interface_updater_thread\n");
        return 1;
    }
    *args = handler_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_interface_updater_thread\n");
        free(handler_args);
        return 1;
    }
    handler_args->signing_keys = sodium_malloc(sizeof(SIGNING_KEY_PAIR));
    if (!(handler_args->signing_keys)) {
        fprintf(stderr, "malloc() failed in create_interface_updater_thread\n");
        free(handler_args);
        return 1;
    }

    if (load_signing_key_pair(handler_args->signing_keys, master_key) != INDIGO_SUCCESS) {
        fprintf(stderr,"load_signing_key_pair() failed in create_interface_updater_thread\n");
        free(handler_args);
        return 1;
    }
    sodium_mprotect_noaccess(handler_args->signing_keys);

    handler_args->queue = queue;
    handler_args->mempool = mempool;
    handler_args->devices = dev_list;
    handler_args->wake = wake_mngr;
    handler_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&packet_handler_thread), handler_args)) {
        free_event_flag(flag);
        free(handler_args);
        return 1;
    }

    *tid = thread;
    return 0;
}


/////////////////////////////////////////////////////////////////
///                                                           ///
///                  THREAD_FUNCTION_HELPERS                  ///
///                                                           ///
/////////////////////////////////////////////////////////////////

int create_handle_array_from_recv_info(const RECV_ARRAY *info, HANDLE **handles, size_t *hCount) {
    if (info == NULL || handles == NULL || hCount == NULL) return 1;

    RECV_INFO *recv = info->head;
    void *temp = malloc(sizeof(HANDLE) * ((info->size) + 2));//we allocate 2 more, 1 for the termination handle
    if (temp == NULL) return 1;                                 //and one for the wake handle

    *handles = temp;
    *hCount = (info->size) + 2;

    for (int i = 0; i < info->size; i++) {
        (*handles)[2 + i] = recv[i].overlapped->hEvent;
    }

    return 0;
}

void free_recv_array(const RECV_ARRAY *info, mempool_t* mempool) {
    for (int i = 0; i < info->size; i++) {
        free_recv_info(&(info->head[i]), mempool);
    }
    free(info->head);
}


////////////////////////////////////////////////////////////////////
///                                                              ///
///                  general_use_functions/misc                  ///
///                                                              ///
////////////////////////////////////////////////////////////////////

void print_discovered_device_info(const PACKET_INFO *dev, FILE *stream) {
    char addr_str[INET_ADDRSTRLEN];
    struct sockaddr_in address = dev->address;
    inet_ntop(AF_INET,&(address.sin_addr.S_un.S_addr),addr_str,INET_ADDRSTRLEN);

    fprintf(stream, "Hostname: ");

    // for (int i = 0; i < MAX_HOSTNAME_LEN; i++) {
    //     if ((dev->hostname[i]) != '\0')fprintf(stream, "%c", dev->hostname[i]);
    // }
    fprintf(stream, "\n");

    fprintf(stream, "IP Address: %s\n",addr_str);

    fprintf(stream,"MAC ADDRESS: ");
    for (uint8_t i = 0; i<dev->mac_address_len; i++) {
        fprintf(stream,"%02x",dev->mac_address[i]);
        if (i != dev->mac_address_len - 1) fprintf(stream,":");
    }
    fprintf(stream,"\n");

    fprintf(stream, "Timestamp: %lld\n\n", dev->timestamp);
    fflush(stream);
}


//////////////////////////////////////////////////////////////
///                                                        ///
///                  DEVICE_LL_UTILITIES                   ///
///                                                        ///
//////////////////////////////////////////////////////////////

int remove_device(PACKET_LIST *devices, const PACKET_INFO *dev) {
    if (devices == NULL) return 1;


    PACKET_NODE *prev = NULL;
    PACKET_NODE *curr = devices->head;

    while (curr != NULL) {
        if (memcmp(curr->packet.mac_address, dev->mac_address, 6) == 0) {
            if (prev == NULL) {
                devices->head = curr->next;
                free(curr);
                return 0;
            }

            prev->next = curr->next;
            free(curr);
            return 0;

        }
        prev = curr;
        curr = curr->next;
    }
    return -1;
}

PACKET_NODE *device_exists(const PACKET_LIST *devices, const PACKET_INFO *dev) {
    if (devices == NULL) return NULL;

    for (PACKET_NODE *curr = devices->head; curr != NULL; curr = curr->next) {
        if (memcmp(curr->packet.mac_address, dev->mac_address, 6) == 0) return curr;
    }
    return NULL;
}


/////////////////////////////////////////////////////////////////
///                                                           ///
///                  IP_SEND_RATE_UTILITIES                   ///
///                                                           ///
/////////////////////////////////////////////////////////////////

IP_RATE_ARRAY *ip_rate_array_new() {
    return calloc(1,sizeof(IP_RATE_ARRAY));
}

void ip_rate_array_free(IP_RATE_ARRAY *array) {
    free(array->first_ip);
    array->first_ip = NULL;
    free(array);
}

int ip_rate_add(IP_RATE_ARRAY *buffer,const uint32_t ip) {
    void *temp;

    if (buffer == NULL) return 1;
    temp = realloc(buffer->first_ip, sizeof(IP_SEND_RATE)*(buffer->size + 1));
    if (temp == NULL) {
        return -1;
    }
    buffer->first_ip = temp;

    ((buffer->first_ip)[buffer->size]).ip = ip;
    //micro optimization: we set the struct to 0 exept for the ip
    memset(((void *)(buffer->first_ip + buffer->size) + sizeof(uint32_t)), 0, sizeof(IP_SEND_RATE) - sizeof(uint32_t));
    buffer->size++;
    return 0;
}


int ip_rate_get(IP_RATE_ARRAY *restrict const buffer,const size_t index , IP_SEND_RATE **restrict const data) {
    if (buffer == NULL) return 1;
    if (index >= buffer->size) return 1;
    *data = &((buffer->first_ip)[index]);
    return 0;
}


int ip_rate_set(IP_RATE_ARRAY *restrict buffer,const size_t index ,const IP_SEND_RATE *restrict const data) {
    if (buffer == NULL || index >= buffer->size || data == NULL) return 1;

    memcpy(buffer->first_ip + index ,data, sizeof(IP_SEND_RATE));

    return 0;
}


int ip_rate_sort(IP_RATE_ARRAY *restrict buffer) {
    if (buffer == NULL) return 1;

    qsort(buffer->first_ip, buffer->size, 1,ip_rate_cmp);
    return 0;
}

int ip_rate_cmp(const void *s1, const void *s2) {
    IP_SEND_RATE *ip1 = (IP_SEND_RATE *)s1;
    IP_SEND_RATE *ip2 = (IP_SEND_RATE *)s2;
    return memcmp(&(ip1->ip), &(ip2->ip), sizeof(uint32_t));
}

int ip_rate_search(IP_RATE_ARRAY *restrict buffer, const uint32_t ip, size_t *const index) {
    size_t bttm, mid, top;

    if (buffer->size == 0) return -1;

    bttm = 0;
    top = buffer->size;

    while (top > 1){
        mid = top / 2;

        if (ip >= (buffer->first_ip)[bttm + mid].ip)
            bttm += mid;

        top -= mid;
    }

    if (ip == (buffer->first_ip)[bttm].ip) {
        if (index != NULL) *index = bttm;
        return 1;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////
///                                                              ///
///                  EXPECTED_PACKET_UTILITIES                   ///
///                                                              ///
////////////////////////////////////////////////////////////////////

//use hash table

int cmp_exp_pack(void* pack1, void* pack2) {
//todo: the function should have a the return logic of memcmp
    exp_pack_t *exp_pack1 = (exp_pack_t *)pack1, exp_pack_t *exp_pack2 = (exp_pack_t *)pack2;
    if ((exp_pack1->socket == exp_pack2->socket) &&
        (exp_pack1->address == exp_pack2->address) &&
        (exp_pack1->type == exp_pack2->type) &&
        (memcmp(exp_pack1->packet_id, exp_pack2->packet_id, 16) == 0)) return 0;
    return memcmp(exp_pack1->packet_id, exp_pack2->packet_id, 16);//problematic
}