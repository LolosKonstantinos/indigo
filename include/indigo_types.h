//
// Created by Constantin on 20/08/2025.
//

#ifndef INDIGO_TYPES_H
#define INDIGO_TYPES_H
#ifdef _WIN32
#include <winsock2.h>
#endif
#include <stdint.h>
#include <sodium.h>

typedef struct remote_device{
    SOCKET *socket;
    int port;
    uint32_t ip;
    unsigned char mac_addr[6];
    unsigned char peer_public_key[crypto_box_PUBLICKEYBYTES];
    uint16_t dev_status_flag;
} remote_device;

#endif //INDIGO_TYPES_H
