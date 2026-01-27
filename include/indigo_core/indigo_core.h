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

#endif

#include <pthread.h>


//for get_discovery_sockets()
typedef struct SOCKET_LL_NODE {
    struct SOCKET_LL_NODE *next;
    SOCKET sock;
}SOCKET_NODE;

typedef struct SOCKET_LL {
    SOCKET_NODE *head;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
}SOCKET_LL;

#endif //INDIGO_DEVICE_DISCOVERY_H
