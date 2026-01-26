//
// Created by Κωνσταντίνος on 4/16/2025.
//
//todo-> define the error codes after the system is completed
#ifndef INDIGO_DEVICE_DISCOVERY_H
#define INDIGO_DEVICE_DISCOVERY_H


#define ON 1
#define OFF 0


// #define SIGNATURE_REQUEST_PROCESSING_RATE 1 //1 request per second
// #define SIGNATURE_REQUEST_MAX_PER_IP_INTERVAL 6


//for now, it's ok, later we will need to add linux libraries
#ifdef _WIN32

#include <winsock2.h>
#include <iphlpapi.h>

#endif

#include <pthread.h>


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

/*
//////////////////////////////////////////////////////////////
///                                                        ///
///                  DEVICE_LL_UTILITIES                   ///
///                                                        ///
//////////////////////////////////////////////////////////////
//todo update and use hash tables, the public key is the identifier
//they are thread unsafe, first lock the mutex and then use

int remove_device(PACKET_LIST *devices, const PACKET_INFO *dev);
PACKET_NODE *device_exists(const PACKET_LIST *devices, const PACKET_INFO *dev);

/////////////////////////////////////////////////////////////////
///                                                           ///
///                  IP_SEND_RATE_UTILITIES                   ///
///                                                           ///
/////////////////////////////////////////////////////////////////
// //todo use a hash table
// IP_RATE_ARRAY *ip_rate_array_new();
// void ip_rate_array_free(IP_RATE_ARRAY *array);
// int ip_rate_add(IP_RATE_ARRAY *buffer,const uint32_t ip);
// int ip_rate_get(IP_RATE_ARRAY *restrict const buffer,const size_t index , IP_SEND_RATE **restrict const data);
// int ip_rate_set(IP_RATE_ARRAY *restrict buffer,const size_t index ,const IP_SEND_RATE *restrict const data);
// int ip_rate_sort(IP_RATE_ARRAY *restrict buffer);
// int ip_rate_cmp(const void *s1, const void *s2);
// int ip_rate_search(IP_RATE_ARRAY *restrict buffer, const uint32_t ip, size_t *const index);

////////////////////////////////////////////////////////////////////
///                                                              ///
///                  EXPECTED_PACKET_UTILITIES                   ///
///                                                              ///
////////////////////////////////////////////////////////////////////
//todo use hash table
int push_expected_packet(exp_pack_t *exp_pack); //copies the packet
exp_pack_t *search_exp_pack(exp_pack_t *exp_pack);
int cmp_exp_pack(void* pack1, void* pack2);
*/

#endif //INDIGO_DEVICE_DISCOVERY_H
