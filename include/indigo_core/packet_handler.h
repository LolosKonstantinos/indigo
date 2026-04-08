/*Copyright (c) 2026 Lolos Konstantinos

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
    unsigned char *pkx;
    unsigned char *skx;
}xsr_t;


//eXpected File Packet
typedef struct xfp_t {
    session_id_t session_id;
    time_t expiration_time;
    uint64_t packet_number;//the expected amount of packets
    FILE *file;
}xfp_t;


typedef struct PACKET_HANDLER_ARGS {
    EFLAG *flag;
    EFLAG *wake;
    QUEUE *queue;
    QUEUE *cli_queue;
    QUEUE *send_queue;
    EFLAG *send_flag;
    tree_t *device_tree;
    tree_t *session_tree;
    mempool_t *mempool;
    signing_key_pair_t *signing_keys;
    socket_ll *sockets;
}PACKET_HANDLER_ARGS;

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int *packet_handler_thread(PACKET_HANDLER_ARGS *args);

//utilities

int cmp_xsr(void *s1, void *s2);
int cmp_xfp(void *s1, void *s2);

int create_server_session(Q_FILE_SENDING_REQUEST *fwd
                          , tree_t *dev_tree
                          , tree_t *session_tree
                          , tree_t *xfp_tree
                          , unsigned char pk[crypto_sign_PUBLICKEYBYTES]
                          , socket_ll* sockets, EFLAG *flag);

int create_client_session(const packet_t *packet
                          , const packet_info_t *packet_info
                          , tree_t *dev_tree
                          , tree_t *session_tree
                          , tree_t *xfp_tree
                          , QUEUE *send_queue
);

int sanitize_username(wchar_t username[MAX_USERNAME_LEN]);
#endif //PACKET_HANDLER_H
