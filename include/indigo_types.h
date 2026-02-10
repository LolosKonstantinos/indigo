//
// Created by Constantin on 20/08/2025.
//

#ifndef INDIGO_TYPES_H
#define INDIGO_TYPES_H

#ifdef _WIN32
#include <winsock2.h>
#endif
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_kx.h>
//RDSF == RemoteDeviceStateFlag
#define RDSF_UNVERIFIED     0x0000
#define RDSF_VERIFIED       0x0001

typedef struct remote_device_t{
    time_t expiration_time; //the time until which we consider the device active, updated with any packet
    SOCKET socket;
    uint64_t last_session_serial;
    int port;
    uint32_t ip;
    unsigned char peer_public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char mac_addr[6];
    uint16_t dev_state_flag;
} remote_device_t;


typedef struct file_sending_request_fwd_t {
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    unsigned char key[crypto_kx_PUBLICKEYBYTES];
    wchar_t file_name[MAX_PATH];
    size_t file_size; //the size of the file in bytes
    SOCKET socket;
    int port;
    uint32_t addr;
}file_sending_request_fwd_t;


typedef struct session_id_t {
    uint64_t serial;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
}session_id_t;

typedef struct session_t{
    session_id_t session_id;
    SOCKET socket;
    int port;
    uint32_t ip;
    //the keys bellow are pointers to secure buffers
    unsigned char *receive_key; // the key to decrypt the received data
    unsigned char *transmit_key;    //the key to encrypt data to send
    time_t start_time;
    time_t end_time;
    size_t bytes_moved;
    unsigned char mac_addr[6];
    uint16_t status_flags;
} session_t;

typedef struct active_file_t {
    FILE *fd;
    uint64_t active; //it's a bool but fol alignment reasons it will be 64-bin
    SOCKET socket;
    int port;
    uint32_t ip;
    struct active_file_t *next;
}active_file_t;




/*GLOBAL DEFINITIONS*/
#define	FORCE_INLINE inline __attribute__((always_inline))
#define MAX_PSW_LEN 128

/*inline function definitions*/
static FORCE_INLINE int cmp_rdev(void *s1, void *s2) {
    return memcmp(((remote_device_t *)s1)->peer_public_key, ((remote_device_t *)s2)->peer_public_key, crypto_sign_PUBLICKEYBYTES);
}
#endif //INDIGO_TYPES_H
