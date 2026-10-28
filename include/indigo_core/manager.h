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

#ifndef THREAD_MANAGEMENT_H
#define THREAD_MANAGEMENT_H
#include "indigo_plugin/indigo_plugin_interface.h"

#include <indigo_core/net_io.h>
#include <indigo_core/net_monitor.h>
#include <indigo_core/packet_handler.h>
#include <event_flags.h>
#include <queue.h>
#include <binary_tree.h>

#define EXECUTION_FLAG_NO_UI          0x0001
#define EXECUTION_FLAG_PRIVILEGED     0x0002
#define EXECUTION_FLAG_NO_PLUGINS     0x0004
#define EXECUTION_FLAG_DAEMON         0x0008

typedef struct MANAGER_ARGS {
    void *master_key;
    uint32_t multicast_addr;
    uint16_t port;
    uint16_t flags;
    indigo_plugin_t **plugins;
    uint64_t plugin_count;
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
    char *ui_flag;
} MANAGER_ARGS;

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

/*this thread manages all the application's threads (apart from small worker threads that can be used by any thread),
 *it's responsible for creating the other threads and handling their errors
 *and moving resources between threads*/
int *thread_manager(MANAGER_ARGS *args);

///////////////////////////////////////////////////////////////////
///                                                             ///
///                  THREAD_CREATING_FUNCTIONS                  ///
///                                                             ///
///////////////////////////////////////////////////////////////////


int create_thread_manager(void *master_key, uint16_t port, uint32_t multicast_addr, uint16_t flags,
                          pthread_mutex_t *mutex, pthread_cond_t *cond, char *ui_flag, indigo_plugin_t **plugins,
                          uint64_t plugin_count);


int create_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, socket_ll *sockets, EFLAG *wake_mngr,
                          signing_key_pair_t *keypair, pthread_t *tid);

int create_receiving_thread(RECV_ARGS **args, socket_ll *sockets, QUEUE *packet_queue, EFLAG *ph_flag,
                            mempool_t *mempool, EFLAG *wake_mngr, uint32_t multicast_addr, int port, pthread_t *tid);

int create_interface_updater_thread(INTERFACE_UPDATE_ARGS **args, int port, uint32_t multicast_address,
                                    EFLAG *wake_mngr, socket_ll *sockets, pthread_t *tid);

int create_packet_handler_thread(PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *ui_queue, QUEUE *send_queue,
                                 EFLAG *send_flag, mempool_t *mempool, ducktable_t *device_tree,
                                 tree_t *known_keys_tree, socket_ll *sockets, signing_key_pair_t *keypair,
                                 pthread_t *tid);

#endif // THREAD_MANAGEMENT_H
