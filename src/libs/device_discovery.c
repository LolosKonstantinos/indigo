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


/////////////////////////////////////////////
///                                       ///
///    get_discovery_sockets() helpers    ///
///                                       ///
/////////////////////////////////////////////


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


int send_discovery_packet(int port, uint32_t multicast_addr, SOCKET socket, SEND_INFO *info) {
    WSABUF *buf = NULL;
    DWORD *numofbytes = NULL;
    struct sockaddr_in *dest = NULL;
    OVERLAPPED *overlapped = NULL;

    DISCV_PAC pac;

    int retVal = 0;

    //____memory_allocations____//

    //allocate the buffer
    buf = (WSABUF *)malloc(sizeof(WSABUF));
    if (buf == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }
    buf->buf = malloc(sizeof(DISCV_PAC));
    buf->len = sizeof(DISCV_PAC);

    //allocate for the number of bytes transfered
    numofbytes = malloc(sizeof(DWORD));
    if (numofbytes == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }
    //allocate the sockaddr_in
    dest = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if (dest == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }
    //allocate the overlapped structure
    overlapped = (OVERLAPPED *)calloc(1,sizeof(OVERLAPPED));
    if (overlapped == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }
    overlapped->hEvent = WSACreateEvent();
    if (overlapped->hEvent == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "WSACreateEvent() failed in send_discovery_packet: %d\n",WSAGetLastError());
        goto cleanup;
    }

    //____initialize the parameters____//

    //the buffer
    prep_discovery_packet(&pac, MSG_INIT_PAC);
    memcpy(buf->buf,&pac,sizeof(DISCV_PAC));

    //sockaddr_in
    memset(dest,0,sizeof(struct sockaddr_in));
    dest->sin_family = AF_INET;
    dest->sin_port = port;
    dest->sin_addr.S_un.S_addr = multicast_addr;


    retVal = WSASendTo(socket,buf,1,numofbytes,MSG_DONTROUTE,(struct sockaddr *)dest,sizeof(struct sockaddr),overlapped,NULL);
    if (retVal == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            //todo: there are errors related to connectivity and are not fault of the programmer, address them later
            fprintf(stderr, "WSASendTo() failed in send_discovery_packet: %d\n", WSAGetLastError());
            goto cleanup;
        }
    }

    info->dest = dest;
    info->buf = buf;
    info->overlapped = overlapped;
    info->bytes = numofbytes;
    info->socket = socket;

    return 0;

    cleanup:
    if (buf != NULL) {
        free(buf->buf);
        free(buf);
    }
    if (overlapped != NULL) {
        WSACloseEvent(overlapped->hEvent);
        free(overlapped);
    }
    free(numofbytes);
    free(dest);
    return 1;
}

int receive_discv_packet(SOCKET socket, RECV_INFO *info) {
    struct sockaddr *source = NULL;
    int *fromLen = NULL;
    WSABUF *buf = NULL;
    OVERLAPPED *overlapped = NULL;
    RECV_INFO *recv_data = NULL;
    DWORD *flags = NULL, *bytes_recv = NULL;
    int retVal;

    //the sender's details
    source = (struct sockaddr *)malloc(sizeof(struct sockaddr));
    if (source == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }

    //size of sender's details
    fromLen = (int *)malloc(sizeof(int));
    if (fromLen == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }
    *fromLen = sizeof(struct sockaddr);

    //the buffer that holds the received message
    buf = (WSABUF *)malloc(sizeof(WSABUF));
    if (buf == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }
    //the actual buffer inside the WSABUF struct
    buf->buf = malloc(sizeof(DISCV_PAC));
    if (buf->buf == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }
    buf->len = sizeof(DISCV_PAC);

    overlapped = (OVERLAPPED *)calloc(1,sizeof(OVERLAPPED));
    if (overlapped == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }
    overlapped->hEvent = WSACreateEvent();
    if (overlapped->hEvent == WSA_INVALID_EVENT) {
        perror("Failed to create event for socket");
        goto cleanup;
    }

    flags = calloc(1,sizeof(DWORD));
    if (flags == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }

    bytes_recv = calloc(1,sizeof(DWORD));
    if (bytes_recv == NULL) {
        perror("Failed to allocate memory for socket");
        goto cleanup;
    }

    info->buf = buf;
    info->overlapped = overlapped;
    info->source = source;
    info->fromLen = fromLen;
    info->bytes_recv = bytes_recv;
    info->flags = flags;
    info->socket = socket;

    retVal = WSARecvFrom(socket,buf,1,bytes_recv,flags,source,fromLen,overlapped,NULL);

    if (retVal == SOCKET_ERROR) {
        //todo not all errors need full shutdown, some are about connectivity
        if (WSAGetLastError() != WSA_IO_PENDING) {
            fprintf(stderr, "WSARecvFrom() failed in receive_discv_packet\n");
            printf("ERROR: %d\n", WSAGetLastError());
            fflush(stdout);
            goto cleanup;
        }
    }
    return 0;

    cleanup:
    free(source);
    free(fromLen);
    if (buf != NULL) {
        free(buf->buf);
        free(buf);
    }
    if (overlapped != NULL) {
        WSACloseEvent(overlapped->hEvent);
        free(overlapped);
    }
    free(flags);
    free(bytes_recv);
    return 1;
}


//____general_use_functions/misc____//

void prep_discovery_packet(DISCV_PAC *packet, const unsigned pac_type) {
    packet->magic_number = MAGIC_NUMBER;
    packet->pac_version = PAC_VERSION;
    packet->pac_type = pac_type;
    packet->pac_length = sizeof(DISCV_PAC);
    if (gethostname(packet->hostname, MAX_HOSTNAME_LEN) != 0 ) {
        strcpy(packet->hostname, "unknown_hostname");
    }
}

void print_discovered_device_info(DISCOVERED_DEVICE *dev, FILE *stream) {
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

//____EVENT_FLAG_UTILITIES____//

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