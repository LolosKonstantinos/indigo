//
// Created by Κωνσταντίνος on 4/16/2025.
//

#include "device_discovery.h"



/*Creates a link list of sockets used for device discovery
 *the sockets are bound to IPs of different subnets covering the maximum network area.
 *Priority is given to IPs of ethernet adapters over wi-fi adapters
 *returns a pointer to the first node else returns NULL
 */
SOCKET_NODE *get_discovery_sockets(int port, uint32_t multicast_addr) {
    SOCKET_NODE *new_sock = NULL, *first_sock = NULL, *temp_sock = NULL;
    IP_SUBNET *p_ip_subnet = NULL;
    size_t addr_count = 0;
    struct sockaddr_in server; //TODO: find better name
    struct ip_mreq mreq;//the structure for the IP_ADD_MEMBERSHIP socket option
    DWORD optval = 0; // the optval for the IP_MULTICAST_LOOP
    //initialize the multicast address
    mreq.imr_multiaddr.S_un.S_addr = multicast_addr;

    if (get_compatible_interfaces(&p_ip_subnet, &addr_count)) {
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
        if (bind(new_sock->sock,(struct sockaddr *)(&server),sizeof(server))) {
            perror("Failed to bind disc node");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            return NULL;
        }

        mreq.imr_interface.S_un.S_addr = server.sin_addr.S_un.S_addr;
        if (setsockopt(new_sock->sock,IPPROTO_IP,IP_ADD_MEMBERSHIP,(char *)&mreq,sizeof(mreq)) == SOCKET_ERROR) {
            perror("Failed to add membership");
            free_discv_sock_ll(first_sock);
            free(p_ip_subnet);
            return NULL;
        }

        if (setsockopt(new_sock->sock,IPPROTO_IP,IP_MULTICAST_LOOP,(char *)&optval,sizeof(optval)) == SOCKET_ERROR) {
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
        return DDTS_MEMORY_ERROR;
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
                return DDTS_MEMORY_ERROR;
            }
            adapter = temp;
            err = GetAdaptersAddresses(AF_INET,flags,NULL,adapter,&size);
        }
        //if we get another error we return
        if (err != ERROR_SUCCESS) {
            fprintf(stderr,"GetAdaptersAddresses failed.%d\n",err);
            free(adapter);
            return DDTS_WINLIB_ERROR;
        }
    }

    //go through all the adapters
    for (p=adapter;p!=NULL;p=p->Next) {
        //adapters must be Wi-Fi or Ethernet and must be active
        if (((p->IfType == IF_TYPE_ETHERNET_CSMACD) || (p->IfType == IF_TYPE_IEEE80211)) && (p->OperStatus == IfOperStatusUp)){
            //go through all the unicast addresses of the adapter
            for (PIP_ADAPTER_UNICAST_ADDRESS unicast_addr = p->FirstUnicastAddress; unicast_addr != NULL; unicast_addr = unicast_addr->Next) {
                if (unicast_addr->Flags == IP_ADAPTER_ADDRESS_TRANSIENT) continue;

                //TODO: do something for DAD states

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
                        return DDTS_MEMORY_ERROR;
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
    return 0;
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


int send_discovery_packets(int port, uint32_t multicast_addr, SOCKET_LL *sockets, EFLAG *flag, uint32_t pCount, int32_t msec) {
    //temporary variables for memory allocation
    SEND_INFO temp_info = {0}, *sInfo = NULL;
    size_t infolen = 0;
    void *temp;

    HANDLE *handles = NULL;
    size_t hCount = 0;

    int ret_val;
    DWORD wait_ret;
    uint32_t flag_val;
    const int32_t temp_math = msec % 1000;

    struct timespec ts;

    DISCV_PAC packet;
    prep_discovery_packet(&packet, MSG_INIT_PAC);

    pthread_mutex_lock(&sockets->mutex);
    for (SOCKET_NODE *sock = sockets->head; sock != NULL; sock = sock->next){
        temp = calloc(1,sizeof(struct sockaddr_in));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            pthread_mutex_unlock(&sockets->mutex);
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
            goto cleanup;
        }
        temp_info.buf = temp;
        temp_info.buf->buf = NULL;

        temp = malloc(sizeof(DISCV_PAC));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            pthread_mutex_unlock(&sockets->mutex);
            goto cleanup;
        }
        temp_info.buf->buf = temp;
        memcpy(temp_info.buf->buf, &packet, sizeof(struct sockaddr_in));
        temp_info.buf->len = sizeof(DISCV_PAC);

        temp = malloc(sizeof(OVERLAPPED));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            pthread_mutex_unlock(&sockets->mutex);
            goto cleanup;
        }
        temp_info.overlapped = temp;
        temp_info.overlapped->hEvent = WSACreateEvent();
        if (temp_info.overlapped->hEvent == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "WSACreateEvent() failed in send_discovery_packets()\n");
            pthread_mutex_unlock(&sockets->mutex);
            goto cleanup;
        }

        temp = malloc(sizeof(DWORD));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            pthread_mutex_unlock(&sockets->mutex);
            goto cleanup;
        }
        temp_info.bytes = temp;

        temp_info.socket = sock->sock;

        temp = realloc(sInfo, sizeof(SEND_INFO) * (infolen + 1));
        if (temp == NULL) {
            fprintf(stderr, "realloc() failed in send_discovery_packets()\n");
            pthread_mutex_unlock(&sockets->mutex);
            goto cleanup;
        }
        sInfo = temp;
        memcpy(sInfo + infolen, &temp_info, sizeof(SEND_INFO));
        infolen++;
        memset(&temp_info, 0, sizeof(SEND_INFO));//so that we dont double free

        flag_val = get_event_flag(flag);
        if (flag_val & EF_OVERRIDE_IO || flag_val & EF_TERMINATION) goto cleanup;

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
                goto cleanup;
            }
        }
    }
    pthread_mutex_unlock(&sockets->mutex);

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (msec - temp_math)/1000;
    ts.tv_nsec += temp_math * 1000000;

    flag_val = get_event_flag(flag);
    if (flag_val & EF_OVERRIDE_IO || flag_val & EF_TERMINATION) goto cleanup;

    pthread_mutex_lock(&flag->mutex);
    pthread_cond_timedwait(&flag->cond, &flag->mutex, &ts);

    if (flag->event_flag & EF_TERMINATION) goto cleanup;
    if (flag->event_flag & EF_OVERRIDE_IO) goto cleanup;

    pthread_mutex_unlock(&flag->mutex);

    if(create_handle_array_from_send_info(sInfo, infolen, &handles, &hCount)) {
        fprintf(stderr, "create_handle_array_from_send_info() failed in send_discovery_packets()\n");
        goto cleanup;
    }

    wait_ret = WSAWaitForMultipleEvents(hCount,handles,TRUE,100, FALSE);
    if (wait_ret == WSA_WAIT_FAILED) {
        fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
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
                    goto cleanup;
                }
            }
        }

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (msec - temp_math)/1000;
        ts.tv_nsec += temp_math * 1000000;

        flag_val = get_event_flag(flag);
        if (flag_val & EF_OVERRIDE_IO || flag_val & EF_TERMINATION) goto cleanup;

        pthread_mutex_lock(&flag->mutex);
        pthread_cond_timedwait(&flag->cond, &flag->mutex, &ts);

        if (flag->event_flag & EF_TERMINATION) goto cleanup;
        if (flag->event_flag & EF_OVERRIDE_IO) goto cleanup;

        pthread_mutex_unlock(&flag->mutex);

        if(create_handle_array_from_send_info(sInfo, infolen, &handles, &hCount)) {
            fprintf(stderr, "create_handle_array_from_send_info() failed in send_discovery_packets()\n");
            goto cleanup;
        }

        wait_ret = WSAWaitForMultipleEvents(hCount,handles,TRUE,100, FALSE);
        if (wait_ret == WSA_WAIT_FAILED) {
            fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
            goto cleanup;
        }
        if (wait_ret == WSA_WAIT_TIMEOUT) {
            for (size_t k = 0; k < hCount; k++) {
                wait_ret = WaitForSingleObject(handles[i], 0);
                if (wait_ret == WAIT_OBJECT_0) continue;

                if (wait_ret == WAIT_FAILED) {
                    fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                    goto cleanup;
                }

                if (wait_ret == WAIT_TIMEOUT) {
                    CancelIo(handles[k]);
                }
            }
        }
    }


    free_send_info(&temp_info); // temporary
    for (size_t i = 0; i < infolen; i++) {
        free_send_info(&sInfo[i]);
    }
    free(handles);
    return 0;

    cleanup:
    free_send_info(&temp_info);
    for (size_t i = 0; i < infolen; i++) {
        free_send_info(&sInfo[i]);
    }
    free(handles);
    return 1;
}

int register_single_discovery_receiver(SOCKET sock, RECV_INFO **info) {
    RECV_INFO *temp_info;
    void *temp;

    int recv_ret;


    if (*info == NULL) {
        if (allocate_recv_info(&temp_info)) {
            fprintf(stderr, "allocate_recv_info() failed in send_discovery_packets()\n");
            return 1;
        }

        temp_info->socket = sock;
        temp_info->flags = 0;


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
                free_recv_info(temp_info);
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

int register_multiple_discovery_receivers(SOCKET_LL *sockets, RECV_ARRAY *info, EFLAG *flag) {
    void *temp;
    RECV_INFO *tempinf;

    uint32_t flag_val;

    int recv_ret;

    info->head = NULL;
    info->size = 0;

    pthread_mutex_lock(&sockets->mutex);
    for (SOCKET_NODE *sock = sockets->head; sock != NULL; sock = sock->next) {
        temp = realloc(info->head, (info->size + 1) * sizeof(RECV_INFO));
        if (temp == NULL) {
            fprintf(stderr, "realloc() failed in register_multiple_discovery_receivers()\n");
            return 1;
        }
        info->head = temp;

        if (allocate_recv_info_fields(info->head + info->size)) {
            fprintf(stderr, "allocate_recv_info_fields() failed in register_multiple_discovery_receivers()\n");
            realloc(info->head, (info->size) * sizeof(RECV_INFO)); // we decrease the size by one
            return 1;
        }

        tempinf = info->head + info->size;

        tempinf->socket = sock->sock;
        tempinf->flags = 0;

        info->size++;

        flag_val = get_event_flag(flag);
        if ((flag_val & EF_OVERRIDE_IO) || (flag_val & EF_TERMINATION)) return -1;

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
                return 1;
            }
        }
    }
    pthread_mutex_unlock(&sockets->mutex);
    return 0;
}


/////////////////////////////////////////////////////////////
///                                                       ///
///                  IO_HELPER_FUNCTIONS                  ///
///                                                       ///
/////////////////////////////////////////////////////////////

void prep_discovery_packet(DISCV_PAC *packet, const unsigned pac_type) {
    packet->magic_number = MAGIC_NUMBER;
    packet->pac_version = PAC_VERSION;
    packet->pac_type = pac_type;
    packet->pac_length = sizeof(DISCV_PAC);
    if (gethostname(packet->hostname, MAX_HOSTNAME_LEN) != 0 ) {
        strcpy(packet->hostname, "unknown_hostname");
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

int create_handle_array_from_recv_info(dyn_array *info, HANDLE **handles, size_t *hCount) {
    RECV_INFO *recv_info;
    void *temp = (HANDLE *)malloc(info->size * sizeof(HANDLE));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in create_handle_array_from_send_info\n");
        return 1;
    }

    for (size_t i = 0; i<info->size; i++) {
        recv_info = dyn_array_get(info,i);
        handles[i] = recv_info->overlapped->hEvent;
        free(recv_info);
    }

    *handles = temp;
    *hCount = info->size;
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

int allocate_recv_info(RECV_INFO **info) {
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

    temp = malloc(sizeof (DISCV_PAC));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free((*info)->buf);
        free((*info)->fromLen);
        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->buf->buf = temp;
    (*info)->buf->len = sizeof (DISCV_PAC);

    temp = malloc(sizeof (OVERLAPPED));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free((*info)->buf->buf);
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
        free((*info)->buf->buf);
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
        free((*info)->buf->buf);
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
        free((*info)->buf->buf);
        free((*info)->buf);
        free((*info)->fromLen);
        free((*info)->source);
        free(*info);

        *info = NULL;
        return 1;
    }
    (*info)->bytes_recv = temp;

    (*info)->socket = INVALID_SOCKET;
    (*info)->handles = NULL;
    (*info)->hCount = 0;

    return 0;
}

int allocate_recv_info_fields(RECV_INFO *info) {
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


    temp = malloc(sizeof (WSABUF));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->fromLen);
        free(info->source);
        return 1;
    }
    info->buf = temp;
    info->buf->buf = NULL;

    temp = malloc(sizeof (DISCV_PAC));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->buf->buf = temp;
    info->buf->len = sizeof (DISCV_PAC);

    temp = malloc(sizeof (OVERLAPPED));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->buf->buf);
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
        free(info->buf->buf);
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
        free(info->buf->buf);
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
        free(info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->bytes_recv = temp;

    info->socket = INVALID_SOCKET;
    info->handles = NULL;
    info->hCount = 0;

    return 0;
}

void free_recv_info(const RECV_INFO *info) {
    if (info == NULL) return;


    if (info->buf) {
        free(info->buf->buf);
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

void *send_discovery_thread(void *arg) {

    return NULL;
}

void *recv_discovery_thread(void *arg) {
    return NULL;
}

void *overlapped_io_handler_thread(void *arg) {
    return NULL;
}

void *interface_updater_thread(void *arg) {
    INTERFACE_UPDATE_ARGS *args = arg;

   HANDLE notification_handle = NULL;
    HANDLE handles[2];
    WSAOVERLAPPED overlapped = {0};
    DWORD retVal;
    uint8_t *process_return = malloc(sizeof(uint8_t));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        free(arg);
        return NULL;
    }
    *process_return = 0;

    overlapped.hEvent = WSACreateEvent();
    if (overlapped.hEvent == NULL) {
        perror("WSACreateEvent() failed in device_discovery_sending");
        *process_return = DDTS_WINLIB_ERROR;
        set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        free(arg);
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
                *process_return = DDTS_BUG;
                break;
            case ERROR_NOT_ENOUGH_MEMORY:
                fprintf(stderr, "ERROR_NOT_ENOUGH_MEMORY\n");
                *process_return = DDTS_MEMORY_ERROR;
                break;
            case ERROR_NOT_SUPPORTED:
                fprintf(stderr, "ERROR_NOT_SUPPORTED\n");
                *process_return = DDTS_UNSUPPORTED;
                break;
            default:
                break;
        }

        set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
        set_event_flag(args->wake, EF_WAKE_MANAGER);

        free(arg);
        return process_return;
    }

    while (!termination_is_on(args->flag)) {
        //the function blocks here and waits for an event
        retVal = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

        //error check
        if (retVal == WAIT_FAILED) {
            //
            perror("WaitForMultipleObjects() failed in interface_updater");
            *process_return = DDTS_WINLIB_ERROR;
            set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            free(arg);
            return process_return;
        }
        //check which event was signalled
        if (retVal - WAIT_OBJECT_0 == 1) {
            //interface update
            set_event_flag(args->flag, EF_INTERFACE_UPDATE);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            WSAResetEvent(overlapped.hEvent);
        }
        else if (retVal - WAIT_OBJECT_0 == 0) {
            //termination event
            CancelIPChangeNotify(&overlapped);
            free(arg);
            return process_return;
        }
        else {
            //there is probably an error
            fprintf(stderr, "WaitForMultipleObjects() failed in interface_updater: %d\n",WSAGetLastError());

            set_event_flag(args->flag, EF_TERMINATION | EF_ERROR);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            CancelIPChangeNotify(&overlapped);
            *process_return = DDTS_BUG;
            free(arg);
            return process_return;
        }
    }
        //termination event signalled and loop ended
        CancelIPChangeNotify(&overlapped);
        free(arg);
        return process_return;
}

void *discovery_manager_thread(void *arg) {
    return NULL;
}


//____general_use_functions/misc____//

void print_discovered_device_info(const DISCOVERED_DEVICE *dev, FILE *stream) {
    char addr_str[INET_ADDRSTRLEN];
    struct sockaddr_in address = dev->address;
    inet_ntop(AF_INET,&(address.sin_addr.S_un.S_addr),addr_str,INET_ADDRSTRLEN);

    fprintf(stream, "Hostname: ");

    for (int i = 0; i <MAX_HOSTNAME_LEN; i++) {
        if ((dev->hostname[i]) == '\0')fprintf(stream, "%c", dev->hostname[i]);
    }
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
///                  EVENT_FLAG_UTILITIES                  ///
///                                                        ///
//////////////////////////////////////////////////////////////

EFLAG *create_event_flag() {
    EFLAG *event_flag = (EFLAG *)malloc(sizeof(EFLAG));
    if (event_flag == NULL) {
        return NULL;
    }
    pthread_mutex_init(&(event_flag->mutex), NULL);
    pthread_cond_init(&(event_flag->cond), NULL);
    event_flag->event_flag = 0;
    return event_flag;
}

int free_event_flag(EFLAG *event_flag) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));

    pthread_mutex_destroy(&(event_flag->mutex));
    pthread_cond_destroy(&(event_flag->cond));
    free(event_flag);
    return 0;
}

int init_event_flag(EFLAG *event_flag) {
    if (event_flag == NULL) return 1;
    if (pthread_mutex_init(&(event_flag->mutex), NULL) != 0) return 1;
    if (pthread_cond_init(&(event_flag->cond), NULL) != 0) {
        pthread_mutex_destroy(&(event_flag->mutex));
        return 1;
    }

    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag = 0;
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

int destroy_event_flag(EFLAG *event_flag) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));

    pthread_mutex_destroy(&(event_flag->mutex));
    pthread_cond_destroy(&(event_flag->cond));
    return 0;
}

int set_event_flag(EFLAG *event_flag, uint32_t flag_value) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag = flag_value;
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

int update_event_flag(EFLAG *event_flag, uint32_t flag_value) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag |= flag_value;
    pthread_cond_broadcast(&(event_flag->cond));
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

int reset_event_flag(EFLAG *event_flag) {
    if (event_flag == NULL) return 1;
    pthread_mutex_lock(&(event_flag->mutex));
    event_flag->event_flag = 0;
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;
}

uint32_t get_event_flag(EFLAG *event_flag) {
    uint32_t fvalue = 0;
    if (event_flag == NULL) return 0;
    pthread_mutex_lock(&(event_flag->mutex));
    fvalue = event_flag->event_flag;
    pthread_mutex_unlock(&(event_flag->mutex));
    return fvalue;
}

uint8_t termination_is_on(EFLAG *event_flag) {
    if (event_flag == NULL) return 0;

    pthread_mutex_lock(&(event_flag->mutex));
    if ((event_flag->event_flag) & EF_TERMINATION) {
        pthread_mutex_unlock(&(event_flag->mutex));
        return 1;
    }
    pthread_mutex_unlock(&(event_flag->mutex));
    return 0;

}