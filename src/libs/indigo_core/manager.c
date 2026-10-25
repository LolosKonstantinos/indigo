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

#include <crypto_utils.h>
#include <indigo_core/manager.h>

#include "config.h"
#include "time_utils.h"
#include "indigo_api/indigo_private_api.h"

#include <indigo_errors.h>
#include <unistd.h>
#include <log.h>
#include <errno.h>

#ifdef __linux__
#include <sys/eventfd.h>
#endif

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////
///
int *thread_manager(MANAGER_ARGS *args)
{
    uint16_t port = args->port;
    uint32_t address = args->multicast_addr;
    uint16_t execution_flags = args->flags;

    pthread_mutex_t *ui_mutex = args->mutex;
    pthread_cond_t *ui_cond = args->cond;
    char *ui_control_flag = args->ui_flag;

    indigo_plugin_t **plugins = args->plugins;
    uint64_t plugin_count = args->plugin_count;

    char ui_initialized = 0;

    // for the thread creation
    pthread_t tid_send = pthread_self();
    pthread_t tid_receive = pthread_self();
    pthread_t tid_update = pthread_self();
    pthread_t tid_handler = pthread_self();

    int *send_ret = NULL;
    int *receive_ret = NULL;
    int *update_ret = NULL;
    int *handler_ret = NULL;

    // the pool used for receiving
    mempool_t *mempool = NULL;

    // the active session tree

    ducktable_t *device_table = NULL;
    tree_t *file_tree = NULL;
    tree_t *known_key_tree = NULL;

    // the thread args
    SEND_ARGS *send_args = NULL;
    RECV_ARGS *recv_args = NULL;
    INTERFACE_UPDATE_ARGS *update_args = NULL;
    PACKET_HANDLER_ARGS *handler_args = NULL;

    // for the event handling
    QNODE *qnode = NULL;
    QUEUE *ui_queue = NULL;

    EFLAG *ui_flag = NULL;

    // the discovery sockets list
    socket_ll *sockets = NULL;

    // the key pair
    const void * master_key = NULL;
    signing_key_pair_t *signing_key_pair = NULL;
    unsigned char signing_pk[crypto_sign_PUBLICKEYBYTES];
    // flags
    EFLAG *flag = NULL;
    uint32_t flag_val;

    const uint64_t termination_val = 1;
    const uint64_t wake_val = 2;

    struct timespec manager_timeout;
    void *temp = NULL;

    int *process_return = NULL;
    int ret = 0; // general purpose return value variable

    /*_______________________________________HERE STARTS THE FUNCTIONS LOGIC__________________________________________*/
    master_key = args->master_key;
    free(args);
    args = NULL;

    pthread_mutex_lock(ui_mutex);


    flag = create_event_flag();
    if (flag == NULL) {
        set_event_flag(flag, EF_TERMINATION);
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_fatal("[thread_manager_thread] create_event_flag() failed | return %d", process_return);

        *ui_control_flag = -1;
        pthread_mutex_unlock(ui_mutex);
        pthread_cond_broadcast(ui_cond);

        return process_return;
    }
    process_return = INDIGO_SUCCESS;


    // prepare to create the threads
    // create the device tree
    device_table = new_ducktable(crypto_sign_PUBLICKEYBYTES, offsetof(remote_device_t,peer_pk), sizeof(remote_device_t),16);
    if (device_table == NULL) {
        log_error("[main] new_tree failed");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    ret = new_tree(&file_tree, cmp_ui_file, NULL, sizeof(ui_file_t), BINARY_TREE_FLAG_AVL);
    if (ret) {
        log_error("[main] new_tree failed");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    ret = new_tree(&known_key_tree, key_cmp, NULL, sizeof(known_key_t), BINARY_TREE_FLAG_AVL);
    if (ret) {
        log_error("[main] new_tree failed");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    ret = load_known_keys(known_key_tree);
    if (ret == -1) {
        log_error("[main] load_known_keys() failed due to invalid parameter");
        ret = INDIGO_ERROR_INVALID_PARAM;
        goto cleanup;
    }

    ui_queue = malloc(sizeof(QUEUE));
    if (ui_queue == NULL) {
        log_error("[main] malloc failed");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    ret = init_queue(ui_queue);
    if (ret) {
        log_error("[main] init_queue failed");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    ui_flag = create_event_flag();
    if (ui_flag == NULL) {
        log_error("[main] create_event_flag() failed");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }


    // create the sockets
    sockets = malloc(sizeof(socket_ll));
    if (sockets == NULL) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_fatal("[thread_manager_thread] malloc failed allocating %d bytes for socket linked list | return %d",
            sizeof(socket_ll), INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }
    pthread_mutex_init(&sockets->mutex, NULL);
    pthread_cond_init(&sockets->cond, NULL);
    sockets->head = NULL;

    temp = get_discovery_sockets(port, address);
    if (temp == NULL) {
        log_error("[thread_manager_thread] get_discovery_sockets() failed");
        goto cleanup;
    }
    sockets->head = temp;


    // create the memory pool
    // the initial mempool is about 1MiB, it may be extended automatically if needed
    mempool = new_mempool_manual(1 << 10, sizeof(packet_t) + sizeof(packet_info_t), PAC_ALIGNMENT, 0.5f);
    if (!mempool) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_fatal("[thread_manager_thread] failed to create new memory pool of %lld bytes | return %d",
            (1<<10) * ((sizeof(packet_t) + sizeof(packet_info_t))), INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    // load the signing keys
    signing_key_pair = sodium_malloc(sizeof(signing_key_pair_t));
    if (signing_key_pair == NULL) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_fatal("[thread_manager_thread] sodium_malloc() failed allocating %d bytes for sign keypair | return %d",
            sizeof(signing_key_pair_t), INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    ret = load_signing_key_pair(signing_key_pair, master_key);
    if (ret != INDIGO_SUCCESS) {
        *process_return = ret;
        log_fatal("[thread_manager_thread] failed loading sign key pair | return %d", ret);
        goto cleanup;
    }
    sodium_mprotect_readonly(signing_key_pair);

    // the public key is our identifier and is used far more commonly than the private key
    // the less the time the private key is accessible the better
    memcpy(signing_pk, signing_key_pair->public, crypto_sign_PUBLICKEYBYTES);

    //initialize the indigo_api
    ret = ui_api_init(queue, send_args->queue, handler_args->queue, send_args->flag, known_key_tree);
    if (ret) {
        *process_return = ret;
        log_fatal("[thread_manager_thread] ui_api_init() failed");
        goto cleanup;
    }

    // create threads
    if (create_sending_thread(&send_args, port, address, sockets, flag, signing_key_pair, &tid_send)) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[thread_manager_thread] send thread creation failed | return %d", INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    if (create_packet_handler_thread(&handler_args, flag, ui_queue, send_args->queue, send_args->flag, mempool,
                                     device_table, known_key_tree, sockets, signing_key_pair, &tid_handler)) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[thread_manager_thread] packet handler thread creation failed | return %d", INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    if (create_receiving_thread(&recv_args, sockets, handler_args->queue, handler_args->flag, mempool, flag,
                                address, port, &tid_receive))
    {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[thread_manager_thread] receive thread creation failed | return %d", INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    if (create_interface_updater_thread(&update_args, port, address, flag, sockets, &tid_update)) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[thread_manager_thread] interface update thread creation failed | return %d", INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    //start plugins
    for (uint64_t i = 0; i < plugin_count; i++) {

    }

    clock_gettime(CLOCK_MONOTONIC, &manager_timeout);
    manager_timeout.tv_sec += 30;

    // the main loop
    while (1) {
        pthread_mutex_lock(&(flag->mutex));
        pthread_cond_timedwait(&flag->cond, &flag->mutex,&manager_timeout);
        flag_val = flag->event_flag;
        pthread_mutex_unlock(&flag->mutex);


        if (!(flag_val & EF_WAKE_MANAGER))
            continue;
        reset_single_event(send_args->flag, EF_WAKE_MANAGER);

        // check the thread flags
        /*decide if error is severe enough and
         *restart the thread,
         *enter ultra low-memory state or
         *terminate completely
         */

        // check the interface updater thread
        flag_val = get_event_flag(update_args->flag);
        if (flag_val & EF_TERMINATION) {
            // for now, we terminate the whole operation, later we may pause or continue as we are
            log_info("[thread_manager_thread] interface update thread terminated");
            goto cleanup;
        }

        // check the sending thread
        flag_val = get_event_flag(send_args->flag);
        if (flag_val & EF_TERMINATION) {
            // for now, we terminate the whole operation, later we may pause or continue as we are
            log_info("[thread_manager_thread] send thread terminated");
            goto cleanup;
        }
        //check the packet handler thread
        flag_val = get_event_flag(handler_args->flag);
        if (flag_val & EF_TERMINATION) {
            // for now, we terminate the whole operation, later we may pause or continue as we are
            log_info("[thread_manager_thread] packet handler thread terminated");
            goto cleanup;
        }
        // check the receiving thread
        flag_val = get_event_flag(recv_args->flag);
        if (flag_val & EF_TERMINATION) {
            // for now, we terminate the whole operation, later we may pause or continue as we are
            log_info("[thread_manager_thread] receive thread terminated");
            goto cleanup;
        }
        flag_val = get_event_flag(ui_flag);
        if (flag_val & EF_TERMINATION) {
            log_info("[thread_manager_thread] ui thread terminated");
            goto cleanup;
        }

        ///////////////////////////////////
        //  update live data_structures  //
        ///////////////////////////////////

        // update the device table
        {
            ducktable_iterator_t *ducktable_iterator = NULL;
            remote_device_t *found_rdev = NULL;
            struct timespec ts_ms = mstotimespec(MS_UNTIL_DISCONNECT);
            struct timespec curr_time, time_diff;

            clock_gettime(CLOCK_MONOTONIC, &curr_time);
            manager_timeout = curr_time;
            manager_timeout.tv_sec += 30;

            ducktable_lock(device_table);
            ret = new_ducktable_iterator(device_table, &ducktable_iterator);
            if (ret && !ducktable_iterator) {
                log_warn("[packet_handler_thread] failed to create xsr iterator");
                // TODO: enter low memory state
            }

            while (ducktable_has_next(ducktable_iterator)) {
                found_rdev = ducktable_next(ducktable_iterator);
                time_diff = timespec_diff(&curr_time, &(found_rdev->timestamp));
                if (timespec_cmp(&time_diff, &ts_ms)>=0) {
                    //just remove
                    ducktable_iterator_remove_current(ducktable_iterator);
                }
                else {
                    // branchless minimum
                    manager_timeout = min_timespec(&time_diff, &manager_timeout);
                }
            }
            free_ducktable_iterator(&ducktable_iterator);
            ducktable_unlock(device_table);
        }


    }

#ifdef _WIN32
    WSASetEvent(recv_args->termination_handle);
    WSASetEvent(update_args->termination_handle);
#else
    write(recv_args->termination_fd, &termination_val, 8);
    write(update_args->termination_fd, &termination_val, 8);
#endif
    set_event_flag(send_args->flag, EF_TERMINATION);
    set_event_flag(recv_args->flag, EF_TERMINATION);
    set_event_flag(handler_args->flag, EF_TERMINATION);
    set_event_flag(update_args->flag, EF_TERMINATION);
    set_event_flag(ui_flag, EF_TERMINATION);

    if (pthread_equal(tid_send, pthread_self()) == 0)
        pthread_join(tid_send, (void **)&send_ret);
    if (pthread_equal(tid_receive, pthread_self()) == 0)
        pthread_join(tid_receive, (void **)&receive_ret);
    if (pthread_equal(tid_handler, pthread_self()) == 0)
        pthread_join(tid_handler, (void **)&handler_ret);
    if (pthread_equal(tid_update, pthread_self()) == 0)
        pthread_join(tid_update, (void **)&update_ret);

    free(send_ret);
    free(receive_ret);
    free(update_ret);
    free(handler_ret);

    pthread_mutex_destroy(&sockets->mutex);
    pthread_cond_destroy(&sockets->cond);
    free_discv_sock_ll(sockets->head);
    free(sockets);

    if (pthread_equal(tid_send, pthread_self()) == 0) {
        if (send_args) {
            free_event_flag(send_args->flag);
            destroy_queue(send_args->queue);
            free(send_args->queue);
            free(send_args);
        }
    }
    // receive
    if (pthread_equal(tid_receive, pthread_self()) == 0) {
        if (recv_args) {
#ifdef _WIN32
            WSACloseEvent(recv_args->termination_handle);
            WSACloseEvent(recv_args->wake_handle);
#else
            close(recv_args->termination_fd);
            close(recv_args->wake_fd);
#endif
            free_event_flag(recv_args->flag);
            free(recv_args);
        }
    }
    // updater
    if (pthread_equal(tid_update, pthread_self()) == 0) {
        if (update_args) {
#ifdef _WIN32
            WSACloseEvent(update_args->termination_handle);
#else
            close(update_args->termination_fd);
#endif
            free_event_flag(update_args->flag);
            free(update_args);
        }
    }
    // packet handler
    if (pthread_equal(tid_handler, pthread_self()) == 0) {
        if (handler_args) {
            free_event_flag(handler_args->flag);
            destroy_queue(handler_args->queue);
            free(handler_args->queue);
            free(handler_args);
        }
    }

    free_mempool(mempool);

    free_ducktable(device_table);
    free_tree(file_tree);
    free_tree(known_key_tree);

    sodium_mprotect_readwrite(signing_key_pair);
    sodium_memzero(signing_key_pair, sizeof(signing_key_pair_t));
    sodium_free(signing_key_pair);

    free_event_flag(flag);

#ifdef _WIN32
    WSACleanup();
#endif
    log_info("[thread_manager_thread] thread manager exited successfully with no errors");
    return process_return;

/////////////////////////////////////////////////////
///                                               ///
///                  __CLEANUP__                  ///
///                                               ///
/////////////////////////////////////////////////////
cleanup:

    if (ui_initialized == 0) {
        *ui_control_flag = -1;
        pthread_mutex_unlock(ui_mutex);
        pthread_cond_broadcast(ui_cond);
    }

    // signal termination to all threads
#ifdef _WIN32
    if (recv_args != NULL) {
        WSASetEvent(recv_args->termination_handle);
    }
    if (update_args != NULL) {
        WSASetEvent(update_args->termination_handle);
    }

#else
    if (recv_args != NULL) {
        write(recv_args->termination_fd, &termination_val, 8);
    }
    if (update_args != NULL) {
        write(update_args->termination_fd, &termination_val, 8);
    }
#endif

    if (send_args != NULL)
        set_event_flag(send_args->flag, EF_TERMINATION);
    if (recv_args != NULL)
        set_event_flag(recv_args->flag, EF_TERMINATION);
    if (handler_args != NULL)
        set_event_flag(handler_args->flag, EF_TERMINATION);
    if (update_args != NULL)
        set_event_flag(update_args->flag, EF_TERMINATION);
    if (ui_flag != NULL)
        set_event_flag(ui_flag, EF_TERMINATION);

    // wait for the threads to terminate before we deallocate any resources
    if (pthread_equal(tid_send, pthread_self()) == 0)
        pthread_join(tid_send, (void **)&send_ret);
    if (pthread_equal(tid_receive, pthread_self()) == 0)
        pthread_join(tid_receive, (void **)&receive_ret);
    if (pthread_equal(tid_update, pthread_self()) == 0)
        pthread_join(tid_update, (void **)&update_ret);
    if (pthread_equal(tid_handler, pthread_self()) == 0)
        pthread_join(tid_handler, (void **)&handler_ret);

    free(send_ret);
    free(receive_ret);
    free(update_ret);
    free(handler_ret);

    // free the args of the threads
    // send
    if (pthread_equal(tid_send, pthread_self()) == 0) {
        if (send_args) {
            free_event_flag(send_args->flag);
            destroy_queue(send_args->queue);
            free(send_args->queue);
            free(send_args);

        }
    }
    // receive
    if (pthread_equal(tid_receive, pthread_self()) == 0) {
        if (recv_args) {
#ifdef _WIN32
            WSACloseEvent(recv_args->termination_handle);
            WSACloseEvent(recv_args->wake_handle);
#else
            close(recv_args->termination_fd);
            close(recv_args->wake_fd);
#endif
            free_event_flag(recv_args->flag);
            free(recv_args);
        }
    }
    // updater
    if (pthread_equal(tid_update, pthread_self()) == 0) {
        if (update_args) {
#ifdef _WIN32
            WSACloseEvent(update_args->termination_handle);
#else
            close(update_args->termination_fd);
#endif
            free_event_flag(update_args->flag);
            free(update_args);
        }
    }
    // packet handler
    if (pthread_equal(tid_handler, pthread_self()) == 0) {
        if (handler_args) {
            free_event_flag(handler_args->flag);
            destroy_queue(handler_args->queue);
            free(handler_args->queue);
            free(handler_args);
        }
    }

    if (sockets) {
        pthread_mutex_destroy(&sockets->mutex);
        pthread_cond_destroy(&sockets->cond);
        free_discv_sock_ll(sockets->head);
        free(sockets);
    }

    free_mempool(mempool);

    free_ducktable(device_table);
    free_tree(file_tree);
    free_tree(known_key_tree);

    sodium_mprotect_readwrite(signing_key_pair);
    sodium_memzero(signing_key_pair, sizeof(signing_key_pair_t));
    sodium_free(signing_key_pair);

    free_event_flag(flag);
#ifdef _WIN32
    WSACleanup();
#endif

    log_info("[thread_manager_thread] thread manager exited with errors");

    return process_return;
}

///////////////////////////////////////////////////////////////////
///                                                             ///
///                  THREAD_CREATING_FUNCTIONS                  ///
///                                                             ///
///////////////////////////////////////////////////////////////////


int create_thread_manager(void *master_key, uint16_t port, uint32_t multicast_addr, uint16_t flags,
                          pthread_mutex_t *mutex, pthread_cond_t *cond, char *ui_flag, indigo_plugin_t **plugins,
                          uint64_t plugin_count)
{
    int ret;
    pthread_t thread;
    MANAGER_ARGS *args = malloc(sizeof(MANAGER_ARGS));
    if (args == NULL) {
        return -1;
    }
    args->master_key = master_key;
    args->port = port;
    args->multicast_addr = multicast_addr;
    args->flags = flags;
    args->mutex = mutex;
    args->cond = cond;
    args->ui_flag = ui_flag;

    ret = pthread_create(&thread, NULL, (void *)thread_manager, args);
    if (ret != 0) {
        free(args);
        log_error("[create_thread_manager] pthread_create() failed to create thread manager with error %d", ret);
    }
    return 0;
}

int create_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, socket_ll *sockets, EFLAG *wake_mngr,
                          signing_key_pair_t *keypair, pthread_t *tid)
{
    pthread_t thread;
    EFLAG *send_flag = NULL;
    QUEUE *send_queue = NULL;

    SEND_ARGS *send_args = malloc(sizeof(SEND_ARGS));
    if (send_args == NULL) {
        log_error("[create_sending_thread] malloc() failed allocating %d bytes for sending thread arguments | return 1", sizeof(SEND_ARGS));
        *args = NULL;
        return 1;
    }
    *args = send_args;


    send_queue = malloc(sizeof(QUEUE));
    if (send_queue == NULL) {
        log_error("[create_sending_thread] malloc failed allocating %d bytes for send thread queue", sizeof(QUEUE));
        free(send_args);
        *args = NULL;
        return 1;
    }
    if (init_queue(send_queue)) {
        log_error("[create_sending_thread] init_queue() failed initializing sending thread queue");
        free(send_queue);
        free(send_args);
        *args = NULL;
        return 1;
    }
    send_flag = create_event_flag();
    if (send_flag == NULL) {
        log_error("[create_sending_thread] create_event_flag() failed creating sending thread flag");
        free(send_queue);
        free(send_args);
        *args = NULL;
        return 1;
    }

    send_args->port = port;
    send_args->multicast_addr = multicast_address;
    send_args->sockets = sockets;
    send_args->wake = wake_mngr;
    send_args->sign_keys = keypair;
    send_args->queue = send_queue;
    send_args->flag = send_flag;

    if (pthread_create(&thread, NULL, (void *)(&send_thread), send_args)) {
        free_event_flag(send_flag);
        destroy_queue(send_queue);
        free(send_args);
        log_error("[create_sending_thread] pthread_create() failed to create send thread | return 1 | errno %d", errno);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_receiving_thread(RECV_ARGS **args, socket_ll *sockets, QUEUE *packet_queue, EFLAG *ph_flag,
                            mempool_t *mempool, EFLAG *wake_mngr, uint32_t multicast_addr, int port, pthread_t *tid)
{

    pthread_t thread;

    RECV_ARGS *recv_args = malloc(sizeof(RECV_ARGS));
    if (recv_args == NULL) {
        log_error("[create_receiving_thread] malloc() failed allocating %d bytes for receiving thread arguments | return 1", sizeof(RECV_ARGS));
        return 1;
    }
    *args = recv_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        log_error( "[create_receiving_thread] create_event_flag() failed | return 1");
        free(recv_args);
        return 1;
    }

#ifdef _WIN32
    recv_args->wake_handle = WSACreateEvent();
    if (recv_args->wake_handle == NULL) {
        fprintf(stderr, "WSACreateEvent() failed in create_receiving_thread\n");
        free_event_flag(flag);
        free(recv_args);
        return 1;
    }

    recv_args->termination_handle = WSACreateEvent();
    if (recv_args->termination_handle == NULL) {
        fprintf(stderr, "WSACreateEvent() failed in create_discovery_receiving_thread\n");
        free_event_flag(flag);
        WSACloseEvent(recv_args->wake_handle);
        free(recv_args);
        return 1;
    }
#else
    recv_args->wake_fd = eventfd(0, EFD_NONBLOCK);
    if (recv_args->wake_fd == -1) {
        log_error("[create_receiving_thread] eventfd() failed to create wake event file descriptor | return 1 | errno %d", errno);
        free(recv_args);
        free_event_flag(flag);
        return 1;
    }
    recv_args->termination_fd = eventfd(0, EFD_NONBLOCK);
    if (recv_args->termination_fd == -1) {
        log_error("[create_receiving_thread] eventfd() failed to create termination event file descriptor | return 1 | errno %d", errno);
        close(recv_args->wake_fd);
        free(recv_args);
        free_event_flag(flag);
        return 1;
    }
#endif
    recv_args->packet_queue = packet_queue;
    recv_args->ph_flag = ph_flag;
    recv_args->mempool = mempool;
    recv_args->sockets = sockets;
    recv_args->wake = wake_mngr;
    recv_args->multicast_addr = multicast_addr;
    recv_args->port = port;
    recv_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&recv_thread), recv_args)) {
        free_event_flag(flag);
        free(recv_args);
        log_error("[create_receiving_thread] pthread_create() failed to create receive thread | return 1 | errno %d", errno);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_interface_updater_thread(INTERFACE_UPDATE_ARGS **args, int port, uint32_t multicast_address,
                                    EFLAG *wake_mngr, socket_ll *sockets, pthread_t *tid)
{
    pthread_t thread;

    INTERFACE_UPDATE_ARGS *update_args = malloc(sizeof(INTERFACE_UPDATE_ARGS));
    if (update_args == NULL) {
        log_error("[create_interface_updater_thread] malloc() failed allocating %d bytes for updater thread arguments | return 1",
            sizeof(INTERFACE_UPDATE_ARGS));
        return 1;
    }
    *args = update_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        log_error("[create_interface_updater_thread] create_event_flag() failed | return 1");
        free(update_args);
        return 1;
    }
#ifdef _WIN32
    update_args->termination_handle = WSACreateEvent();
    if (update_args->termination_handle == NULL) {
        fprintf(stderr, "WSACreateEvent() failed in create_interface_updater_thread\n");
        free_event_flag(flag);
        free(update_args);
        return 1;
    }
#else
    update_args->termination_fd = eventfd(0, EFD_NONBLOCK);
    if (update_args->termination_fd == -1) {
        log_error("[create_interface_updater_thread] eventfd() failed to create termination event file descriptor | return 1 | errno %d", errno);
        free_event_flag(flag);
        free(update_args);
        return 1;
    }
#endif
    update_args->port = port;
    update_args->multicast_addr = multicast_address;
    update_args->sockets = sockets;
    update_args->wake = wake_mngr;
    update_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&interface_updater_thread), update_args)) {
        free_event_flag(flag);
        free(update_args);
        log_error("[create_interface_updater_thread] pthread_create() failed to create updater thread | return 1 | errno %d", errno);
        return 1;
    }

    *tid = thread;
    return 0;
}

int create_packet_handler_thread(PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *ui_queue, QUEUE *send_queue,
                                 EFLAG *send_flag, mempool_t *mempool, ducktable_t *device_tree,
                                 tree_t *known_keys_tree, socket_ll *sockets, signing_key_pair_t *keypair,
                                 pthread_t *tid)
{

    pthread_t thread;
    QUEUE *queue;
    EFLAG *flag;

    PACKET_HANDLER_ARGS *handler_args = malloc(sizeof(PACKET_HANDLER_ARGS));
    if (handler_args == NULL) {
        log_error("[create_packet_handler_thread] malloc() failed allocating %d bytes for packet handler thread arguments | return 1",
            sizeof(PACKET_HANDLER_ARGS));
        *args = NULL;
        return 1;
    }
    *args = handler_args;

    queue = malloc(sizeof(QUEUE));
    if (queue == NULL) {
        log_error("[create_packet_handler_thread] malloc() failed allocating %d bytes for packet handler thread queue | return 1",
            sizeof(QUEUE));
        free(handler_args);
        *args = NULL;
        return 1;
    }
    if (init_queue(queue)) {
        log_error("[create_packet_handler_thread] init_queue failed initializing packet handler thread queue | return 1");
        free(handler_args);
        free(queue);
        *args = NULL;
        return 1;
    }

    flag = create_event_flag();
    if (flag == NULL) {
        log_error("[create_packet_handler_thread] create_event_flag() failed creating event flag for packet handle thread | return 1");
        free(handler_args);
        destroy_queue(queue);
        free(queue);
        *args = NULL;
        return 1;
    }

    handler_args->sign_keys = keypair;
    handler_args->queue = queue;
    handler_args->send_queue = send_queue;
    handler_args->mempool = mempool;
    handler_args->wake = wake_mngr;
    handler_args->flag = flag;
    handler_args->device_table = device_tree;
    handler_args->known_keys_tree = known_keys_tree;
    handler_args->sockets = sockets;
    handler_args->send_flag = send_flag;
    handler_args->ui_queue = ui_queue;

    if (pthread_create(&thread, NULL, (void *)(&packet_handler_thread), handler_args)) {
        free(handler_args);
        log_error("[create_packet_handler_thread] pthread_create() failed to create packet handler thread | return 1 | errno %d", errno);
        return 1;
    }

    *tid = thread;
    return 0;
}
