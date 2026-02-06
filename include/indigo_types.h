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
#include <sodium/crypto_box.h>
#include <sodium/crypto_kx.h>

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

typedef struct rdev_node_t {
    remote_device_t *remote_device;
    struct rdev_node_t *next;
}rdev_node_t;

typedef struct rdev_ll_t {
    rdev_node_t *head;
    pthread_mutex_t mutex;
    char new_device; //when there is a new device this is changed to non zero
}rdev_ll_t;


typedef struct file_sending_request_fwd_t {
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    unsigned char key[crypto_kx_PUBLICKEYBYTES];
    wchar_t file_name[MAX_PATH];
    size_t file_size; //the size of the file in bytes
}file_sending_request_fwd_t;

typedef struct session_t{
    SOCKET *socket;
    int port;
    uint32_t ip;
    unsigned char peer_public_key[crypto_kx_PUBLICKEYBYTES];
    //the keys bellow are pointers to secure buffers
    unsigned char *session_receive_key; // the key to decrypt the received data
    unsigned char *session_send_key;    //the key to encrypt data to send
    time_t start_time;
    time_t end_time;
    size_t bytes_moved;
    unsigned char mac_addr[6];
    uint16_t status_flags;
} session_t;

/*GLOBAL DEFINITIONS*/
#define MAX_PSW_LEN 128

#endif //INDIGO_TYPES_H
