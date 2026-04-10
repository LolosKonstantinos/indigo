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
#include <indigo_core/net_io.h>
#include <indigo_core/net_monitor.h>
#include <indigo_core/packet_handler.h>
#include <event_flags.h>
#include <Queue.h>
#include <binary_tree.h>

typedef struct MANAGER_ARGS {
    int port;
    uint32_t multicast_addr;
    EFLAG *flag;
    void *master_key;
    QUEUE *queue;
    tree_t *device_tree;
}MANAGER_ARGS;

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

/*this thread manages all the application's threads (apart from small worker threads that can be used by any thread),
 *it's responsible for creating the other threads and handling their errors
 *and moving resources between threads*/
int *thread_manager_thread(MANAGER_ARGS *args);

///////////////////////////////////////////////////////////////////
///                                                             ///
///                  THREAD_CREATING_FUNCTIONS                  ///
///                                                             ///
///////////////////////////////////////////////////////////////////

int cancel_device_discovery(pthread_t tid, EFLAG *flag);

int create_thread_manager_thread(MANAGER_ARGS **args, int port, uint32_t multicast_address, tree_t* dev_tree, pthread_t *tid);

int create_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, socket_ll *sockets,
                          EFLAG *wake_mngr, QUEUE* queue, const void* master_key, pthread_t *tid);

int create_receiving_thread(RECV_ARGS **args, socket_ll *sockets, QUEUE *queue, mempool_t* mempool, EFLAG *wake_mngr, pthread_t *tid);

int create_interface_updater_thread(INTERFACE_UPDATE_ARGS **args, int port, uint32_t multicast_address, EFLAG *wake_mngr,
    EFLAG* override_flags[], socket_ll *sockets, pthread_t *tid);

int create_packet_handler_thread(PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *queue, QUEUE* send_queue,
                                 EFLAG* send_flag, mempool_t* mempool, tree_t* device_tree, const void *master_key, socket_ll* sockets, pthread_t *tid);
#endif //THREAD_MANAGEMENT_H
