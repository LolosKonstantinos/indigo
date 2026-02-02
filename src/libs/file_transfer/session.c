//
// Created by Constantin on 10/08/2025.
//

#include "session.h"
#include"indigo_errors.h"

//a session object is to be used after a session is initiated to send and receive files

// struct session_t{
//     SOCKET *socket;
//     int port;
//     uint32_t ip;
//     unsigned char mac_addr[6];
//     unsigned char peer_public_key[crypto_kx_PUBLICKEYBYTES];
//     //the keys bellow are pointers to secure buffers
//     unsigned char *session_receive_key; // the key to decrypt the received data
//     unsigned char *session_send_key;    //the key to encrypt data to send
//     time_t start_time;
//     time_t end_time;
//     size_t bytes_sent;
//     size_t bytes_received;
//     uint8_t status_flags;
// };
