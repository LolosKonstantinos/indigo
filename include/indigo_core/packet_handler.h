/*
Copyright (c) 2026 Lolos Konstantinos

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
#include <stddef.h>
#include <stdint.h>

#define EXPIRATION_TIME 15

// eXpected Signing Response
typedef struct xsr_t {
    time_t expiration_time;
    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char id[crypto_sign_PUBLICKEYBYTES];
    unsigned char *pkx;
    unsigned char *skx;
} xsr_t;

typedef struct PACKET_HANDLER_ARGS {
    EFLAG *flag;
    EFLAG *wake;
    QUEUE *queue;
    QUEUE *ui_queue;
    QUEUE *send_queue;
    EFLAG *send_flag;
    tree_t *device_tree;
    tree_t *known_keys_tree;
    tree_t *session_tree;
    mempool_t *mempool;
    signing_key_pair_t *sign_keys;
    socket_ll *sockets;
} PACKET_HANDLER_ARGS;

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

int *packet_handler_thread(PACKET_HANDLER_ARGS *args);

// utilities

int cmp_xsr(void *s1, void *s2);
void free_xsr(void *xsr);

int create_server_session(Q_FILE_SENDING_REQUEST *fwd, tree_t *dev_tree, tree_t *session_tree,
                          unsigned char pk[crypto_sign_PUBLICKEYBYTES], socket_ll *sockets, EFLAG *flag);

int create_client_session(const packet_t *packet, const packet_info_t *packet_info, tree_t *dev_tree,
                          tree_t *session_tree, QUEUE *send_queue, EFLAG *send_flag);

int init_packet_routine(packet_t *packet, packet_info_t *packet_info, tree_t *dev_tree, tree_t *xsr_tree,
                        tree_t *known_keys_tree, char username[MAX_USERNAME_LEN * sizeof(uint32_t) + 1],
                        signing_key_pair_t *signing_keys, socket_ll *sockets, EFLAG *flag);

int signing_request_routine(packet_t *packet, packet_info_t *packet_info, tree_t *dev_tree, tree_t *xsr_tree,
                            tree_t *known_keys_tree, signing_key_pair_t *signing_keys, socket_ll *sockets, EFLAG *flag);

int signing_response_routine(packet_t *packet, packet_info_t *packet_info, tree_t *dev_tree, tree_t *xsr_tree,
                             signing_key_pair_t *signing_keys, socket_ll *sockets, EFLAG *flag);

int file_sending_request_routine(packet_t *packet, packet_info_t *packet_info, tree_t *dev_tree, tree_t *session_tree,
                                 signing_key_pair_t *signing_keys, socket_ll *sockets, EFLAG *flag);

int file_chunk_routine(packet_t *packet, packet_info_t *packet_info, tree_t *session_tree,
                       signing_key_pair_t *signing_keys, socket_ll *sockets, EFLAG *flag);

int resend_routine(packet_t *packet, QUEUE *send_queue, EFLAG *send_flag);

int stop_file_transmission_routine(packet_t *packet, QUEUE *send_queue, EFLAG *send_flag);
int pause_file_transmission_routine(packet_t *packet, QUEUE *send_queue, EFLAG *send_flag);
int continue_file_transmission_routine(packet_t *packet, QUEUE *send_queue, EFLAG *send_flag);


#endif // PACKET_HANDLER_H
