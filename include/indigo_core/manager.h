//
// Created by Constantin on 26/01/2026.
//

#ifndef THREAD_MANAGEMENT_H
#define THREAD_MANAGEMENT_H
#include <indigo_core/indigo_core.h>
#include <indigo_core/net_io.h>
#include <indigo_core/net_monitor.h>
#include <indigo_core/packet_handler.h>
#include <event_flags.h>
#include <Queue.h>

typedef struct MANAGER_ARGS {
    int port;
    uint32_t multicast_addr;
    EFLAG *flag;
    void *master_key;
}MANAGER_ARGS;
//todo use the public key as the device id, but dont rely only on the packet received
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

int create_thread_manager_thread(MANAGER_ARGS **args, const int port, const uint32_t multicast_address, pthread_t *tid);
int create_discovery_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, SOCKET_LL *sockets, EFLAG *wake_mngr, pthread_t *tid, unsigned char public_key[crypto_sign_PUBLICKEYBYTES] );
int create_receiving_thread(RECV_ARGS **args, SOCKET_LL *sockets, QUEUE *queue, mempool_t* mempool, EFLAG *wake_mngr, pthread_t *tid);
int create_interface_updater_thread(INTERFACE_UPDATE_ARGS **args, int port, uint32_t multicast_address, EFLAG *wake_mngr, SOCKET_LL *sockets, pthread_t *tid);
int create_packet_handler_thread(PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *queue, mempool_t* mempool, const void *master_key, pthread_t *tid);
#endif //THREAD_MANAGEMENT_H
