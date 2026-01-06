//
// Created by Constantin on 10/08/2025.
//

#ifndef SESSION_H
#define SESSION_H

//for TCP/IP communication (not for device discovery)
#define TCP_PORT 4363

#define SESSION_MAX_RETRIES 4

#include <pthread.h>
#include <stdint.h>
#include "session_types.h"
#include "crypto_utils.h"
#include  <sodium.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

typedef struct SESSION SESSION;
#define SESSION_SOCKET 0x01
#define SESSION_PORT 0x02
#define SESSION_IP 0x03
#define SESSION_MAC 0x04
#define SESSION_PEER_PUBKEY 0x05
#define SESSION_SESSION_SYMMETRIC_KEY 0x06
#define SESSION_TID 0x07
#define SESSION_START_TIME 0x08
#define SESSION_END_TIME 0x09
#define SESSION_BYTES_SENT 0x0A
#define SESSION_BYTES_RECEIVED 0x0B


SESSION *session_new();
void session_destroy(SESSION *session);

int init_session(int port, uint32_t address, SESSION *session);


int exchange_public_keys(unsigned char public_key[crypto_box_PUBLICKEYBYTES],
                        SIGNING_KEY_PAIR *key_pair,
                        unsigned char peer_key[crypto_box_PUBLICKEYBYTES]);

int send_key_exchange_packet(const SOCKET *sock,const uint32_t addr,const int port,const void *const packet);
int wait_for_key_exchange_packet(const SOCKET *sock, uint32_t addr, int port, SESSION_MSG_TYPE *type,
                                 void **data, size_t *size);

int session_set(SESSION *session, uint16_t field, void *value, size_t size);
int gen_session_id(unsigned char session_id[SESSION_ID_BYTES]);
int session_message_new(void ** msg, uint16_t type, void *data, uint16_t size);
#endif //SESSION_H
