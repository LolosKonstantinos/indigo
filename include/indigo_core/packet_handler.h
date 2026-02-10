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
#include "indigo_types.h"
#include <binary_tree.h>

#define EXPIRATION_TIME 15

//eXpected Signing Response
typedef struct xsr_t {
    time_t expiration_time;
    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
}xsr_t;


//eXpected File Packet
typedef struct xfp_t {
    session_id_t session_id;
    time_t expiration_time;
    uint64_t packet_number;//the expected amount of packets
    FILE *file;
    unsigned char *receive_key;
}xfp_t;


typedef struct PACKET_HANDLER_ARGS {
    EFLAG *flag;
    EFLAG *wake;
    QUEUE *queue;
    QUEUE *cli_queue;
    QUEUE *send_queue;
    tree_t *device_tree;
    tree_t *session_tree;
    mempool_t *mempool;
    SIGNING_KEY_PAIR *signing_keys;
}PACKET_HANDLER_ARGS;

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int *packet_handler_thread(PACKET_HANDLER_ARGS *args);

int cmp_xsr(void *s1, void *s2);
int cmp_xfp(void *s1, void *s2);
#endif //PACKET_HANDLER_H
