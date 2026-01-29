//
// Created by Constantin on 20/08/2025.
//

#ifndef INDIGO_TYPES_H
#define INDIGO_TYPES_H

#ifdef _WIN32
#include <winsock2.h>
#endif
#include <stdint.h>
#include <sodium/crypto_box.h>

//RDSF == RemoteDeviceStateFlag
#define RDSF_UNVERIFIED     0x0000
#define RDSF_VERIFIED       0x0001

typedef struct remote_device_t{
    time_t expiration_time; //the time until which we consider the device active, updated with any packet
    SOCKET socket;
    int port;
    uint32_t ip;
    unsigned char peer_public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char mac_addr[6];
    uint16_t dev_state_flag;
} remote_device_t;

#endif //INDIGO_TYPES_H
