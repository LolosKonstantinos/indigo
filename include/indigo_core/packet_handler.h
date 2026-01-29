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

typedef struct expected_packet_t {
    time_t expiration_time;
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    unsigned char nonce[INDIGO_NONCE_SIZE];
    uint64_t serial_number_range[2]; //describes the range of serial numbers we expect (usually with files)
    unsigned char type;
    unsigned char zero[7];
}expected_packet_t;

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
