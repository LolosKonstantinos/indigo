//
// Created by Constantin on 10/08/2025.
//

#ifndef SESSION_H
#define SESSION_H

//for TCP/IP communication (not for device discovery)
#define TCP_PORT 57362

#include <pthread.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

typedef struct SESSION{
   SOCKET *socket;
   int port;
   uint32_t ip;
   pthread_t tid;
} SESSION;

int init_session(int port, uint32_t address, SESSION* session);

#endif //SESSION_H
