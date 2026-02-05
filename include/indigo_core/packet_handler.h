//
// Created by Constantin on 26/01/2026.
//

#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H
#include <indigo_core/net_io.h>
#include <event_flags.h>
#include <mempool.h>
#include <crypto_utils.h>
#include <Queue.h>

#include "hash_table.h"

#define EXPIRATION_TIME 15

//eXpected Signing Response
typedef struct xsr_t {
    time_t expiration_time;
    unsigned char nonce[INDIGO_NONCE_SIZE];
}xsr_t;

typedef struct xsr_key_t {
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
}xsr_key_t;

//eXpected File Packet
typedef struct xfp_t {
    time_t expiration_time;
    uint64_t range[2];//describes the range of serial numbers we expect
    FILE *file;
}xfp_t;

typedef struct xfp_key_t {
    uint64_t session_id;
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
}xfp_key_t;

typedef struct PACKET_HANDLER_ARGS {
    EFLAG *flag;
    EFLAG *wake;
    QUEUE *queue;
    hash_table_t *device_table;
    mempool_t *mempool;
    SIGNING_KEY_PAIR *signing_keys;
}PACKET_HANDLER_ARGS;

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int *packet_handler_thread(PACKET_HANDLER_ARGS *args);
#endif //PACKET_HANDLER_H
