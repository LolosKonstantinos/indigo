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
#include <indigo_errors.h>
#include <stdint.h>
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
int *thread_manager_thread(MANAGER_ARGS *args)
{
    // for the thread creation
    pthread_t tid_send = pthread_self();
    pthread_t tid_receive = pthread_self();
    pthread_t tid_update = pthread_self();
    pthread_t tid_handler = pthread_self();

    int *send_ret = NULL;
    int *receive_ret = NULL;
    int *update_ret = NULL;
    int *handler_ret = NULL;

    EFLAG *override_flags[3];

    QUEUE *packet_queue = NULL;
    QUEUE *send_queue = NULL;

    // the pool used for receiving
    mempool_t *mempool = NULL;

    // the active session tree
    tree_t session_tree; // todo: write cmp_session function and create the tree

    // the thread args
    SEND_ARGS *send_args = NULL;
    RECV_ARGS *recv_args = NULL;
    INTERFACE_UPDATE_ARGS *update_args = NULL;
    PACKET_HANDLER_ARGS *handler_args = NULL;

    // for the event handling
    QNODE *qnode_pop = NULL;

    // the discovery sockets list
    socket_ll *sockets = NULL;

    // the key pair
    signing_key_pair_t *signing_key_pair = NULL;
    unsigned char signing_pk[crypto_sign_PUBLICKEYBYTES];
    // flags
    uint32_t flag_val;

    const uint64_t termination_val = 1;
    const uint64_t wake_val = 2;

    void *temp = NULL;

    int *process_return = NULL;
    int ret_val = 0; // general purpose return value variable

    /*_______________________________________HERE STARTS THE FUNCTIONS LOGIC__________________________________________*/

    // allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        free(args);
        log_fatal("[thread_manager_thread] malloc failed allocating %d bytes for thread return value | return NULL", sizeof(int));
        return NULL;
    }
    *process_return = INDIGO_SUCCESS;

    // prepare to create the threads

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

    temp = get_discovery_sockets(args->port, args->multicast_addr);
    if (temp == NULL) {
        log_error("[thread_manager_thread] get_discovery_sockets() failed");
        goto cleanup;
    }
    sockets->head = temp;

    // create the packet queue
    packet_queue = args->ph_queue;
    send_queue = args->send_queue;

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

    ret_val = load_signing_key_pair(signing_key_pair, args->master_key);
    if (ret_val != INDIGO_SUCCESS) {
        *process_return = ret_val;
        log_fatal("[thread_manager_thread] failed loading sign key pair | return %d", ret_val);
        goto cleanup;
    }
    sodium_mprotect_readonly(signing_key_pair);

    // the public key is our identifier and is used far more commonly than the private key
    // the less the time the private key is accessible the better
    memcpy(signing_pk, signing_key_pair->public, crypto_sign_PUBLICKEYBYTES);

    // create threads
    if (create_sending_thread(&send_args, args->port, args->multicast_addr, sockets, args->flag, send_queue,
                              args->master_key, &tid_send)) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[thread_manager_thread] send thread creation failed | return %d", INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    if (create_packet_handler_thread(&handler_args, args->flag, packet_queue, args->ui_queue, send_queue,
                                     send_args->flag, mempool, args->device_tree, args->master_key, sockets,
                                     &tid_handler)) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[thread_manager_thread] packet handler thread creation failed | return %d", INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    if (create_receiving_thread(&recv_args, sockets, packet_queue, mempool, args->flag, args->multicast_addr, args->port, &tid_receive)) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[thread_manager_thread] receive thread creation failed | return %d", INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    override_flags[0] = handler_args->flag;
    override_flags[1] = recv_args->flag;
    override_flags[2] = send_args->flag;

    if (create_interface_updater_thread(&update_args, args->port, args->multicast_addr, args->flag, override_flags,
                                        sockets, &tid_update)) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[thread_manager_thread] interface update thread creation failed | return %d", INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        goto cleanup;
    }

    // the main loop
    while (!termination_is_on(args->flag)) {
        pthread_mutex_lock(&args->flag->mutex);
        pthread_cond_wait(&args->flag->cond, &args->flag->mutex);
        flag_val = args->flag->event_flag;
        pthread_mutex_unlock(&args->flag->mutex);

        if (termination_is_on(args->flag)) {
            *process_return = 0;
            break;
        }

        if (!(flag_val & EF_WAKE_MANAGER))
            continue;
        reset_single_event(send_args->flag, EF_WAKE_MANAGER);
        // check the thread flags

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

        // todo remove since the packet handler communicates directly with the receiver
        // in this case we just forward to the packet handler
        if (flag_val & EF_NEW_PACKET) {
            qnode_pop = queue_pop(packet_queue, QOPT_NON_BLOCK);
            if (qnode_pop != NULL) {
                if (queue_push(packet_queue, qnode_pop->data, qnode_pop->type)) {
                    destroy_qnode(qnode_pop);
                    log_error("[thread_manager_thread] failed to push packet event to paket handler queue");
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    goto cleanup;
                }
                destroy_qnode(qnode_pop);
                update_event_flag(handler_args->flag, EF_NEW_PACKET);
            }
            reset_single_event(recv_args->flag, EF_NEW_PACKET);
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

    // send args
    free_event_flag(send_args->flag);
    free(send_args);

    // receive args
#ifdef _WIN32
    WSACloseEvent(recv_args->termination_handle);
    WSACloseEvent(recv_args->wake_handle);
#else
    close(recv_args->termination_fd);
    close(recv_args->wake_fd);
#endif
    free_event_flag(recv_args->flag);
    free(recv_args);

    // update args
#ifdef _WIN32
    WSACloseEvent(update_args->termination_handle);
#else
    write(update_args->termination_fd, &termination_val, 8);
#endif
    free_event_flag(update_args->flag);
    free(update_args);

    // handler args
    free_event_flag(handler_args->flag);
    free(handler_args);

    pthread_mutex_destroy(&sockets->mutex);
    pthread_cond_destroy(&sockets->cond);
    free_discv_sock_ll(sockets->head);

    destroy_queue(packet_queue);
    free(packet_queue);

    destroy_queue(send_queue);
    free(send_queue);

    free_mempool(mempool);

    free_event_flag(args->flag);
    free(args);

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
        if (send_args)
            free(send_args->flag);
        free(send_args);
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
        if (handler_args)
            free_event_flag(handler_args->flag);
        free(handler_args);
    }

    if (sockets) {
        pthread_mutex_destroy(&sockets->mutex);
        pthread_cond_destroy(&sockets->cond);
        free_discv_sock_ll(sockets->head);
    }

    destroy_queue(packet_queue);
    free(packet_queue);

    destroy_queue(send_queue);
    free(send_queue);

    free(mempool);

    free_event_flag(args->flag);
    free(args);
    sodium_free(signing_key_pair);
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

int cancel_device_discovery(pthread_t tid, EFLAG *flag)
{
    int *ret = NULL;
    int val;

    set_event_flag(flag, EF_TERMINATION | EF_WAKE_MANAGER);

    if (pthread_equal(tid, pthread_self()) == 0) {
        pthread_join(tid, (void **)&ret);
    }
    log_info("[cancel_device_discovery] thread manager joined main thread");

    if (ret == NULL)
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    val = *ret;
    free(ret);
    return val;
}
int create_thread_manager_thread(MANAGER_ARGS **args, void *master_key, int port, uint32_t multicast_address,
                                 tree_t *dev_tree, QUEUE *ui_queue, QUEUE *ph_queue, QUEUE *send_queue,
                                 QUEUE *manager_queue, pthread_t *tid)
{
    pthread_t thread;

    MANAGER_ARGS *manager_args = malloc(sizeof(MANAGER_ARGS));
    if (manager_args == NULL) {
        log_error("[create_thread_manager_thread] malloc failed allocating %d bytes for thread manager arguments | return 1", sizeof(MANAGER_ARGS));
        return 1;
    }
    *args = manager_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        log_error("[create_thread_manager_thread] failed to create event flap | return 1");
        free(manager_args);
        return 1;
    }

    manager_args->master_key = master_key;
    manager_args->queue = manager_queue;
    manager_args->flag = flag;
    manager_args->port = port;
    manager_args->multicast_addr = multicast_address;
    manager_args->device_tree = dev_tree;
    manager_args->ui_queue = ui_queue;
    manager_args->ph_queue = ph_queue;
    manager_args->send_queue = send_queue;

    if (pthread_create(&thread, NULL, (void *)(&thread_manager_thread), manager_args)) {
        free_event_flag(flag);
        free(*args);
        log_error("[create_thread_manager_thread] pthread_create() failed to create thread manager thread | return 1 | errno %d", errno);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, socket_ll *sockets, EFLAG *wake_mngr,
                          QUEUE *queue, const void *master_key, pthread_t *tid)
{
    pthread_t thread;

    SEND_ARGS *send_args = malloc(sizeof(SEND_ARGS));
    if (send_args == NULL) {
        log_error("[create_sending_thread] malloc() failed allocating %d bytes for sending thread arguments | return 1", sizeof(SEND_ARGS));
        return 1;
    }
    *args = send_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        log_error( "[create_sending_thread] create_event_flag() failed | return 1");
        free(send_args);
        return 1;
    }
    send_args->sign_keys = sodium_malloc(sizeof(signing_key_pair_t));
    if (!send_args->sign_keys) {
        log_error( "[create_sending_thread] sodium_malloc() failed allocating %d bytes for signing key pair | return 1", sizeof(signing_key_pair_t));
        free(send_args);
        return 1;
    }

    if (load_signing_key_pair(send_args->sign_keys, master_key) != INDIGO_SUCCESS) {
        log_error( "[create_sending_thread] load_signing_key_pair() failed | return 1");
        free(send_args);
        return 1;
    }

    send_args->port = port;
    send_args->multicast_addr = multicast_address;
    send_args->sockets = sockets;
    send_args->wake = wake_mngr;
    send_args->flag = flag;
    send_args->queue = queue;

    if (pthread_create(&thread, NULL, (void *)(&send_thread), send_args)) {
        free_event_flag(flag);
        free(send_args);
        log_error("[create_sending_thread] pthread_create() failed to create send thread | return 1 | errno %d", errno);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_receiving_thread(RECV_ARGS **args, socket_ll *sockets, QUEUE *queue, mempool_t *mempool, EFLAG *wake_mngr,
                            uint32_t multicast_addr, int port, pthread_t *tid)
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
    recv_args->queue = queue;
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
                                    EFLAG *wake_mngr, EFLAG *override_flags[3], socket_ll *sockets, pthread_t *tid)
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
    memcpy((void *)((*args)->override_flags), (void *)override_flags, 3 * sizeof(EFLAG *));

    if (pthread_create(&thread, NULL, (void *)(&interface_updater_thread), update_args)) {
        free_event_flag(flag);
        free(update_args);
        log_error("[create_interface_updater_thread] pthread_create() failed to create updater thread | return 1 | errno %d", errno);
        return 1;
    }

    *tid = thread;
    return 0;
}

int create_packet_handler_thread(PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *queue, QUEUE *ui_queue,
                                 QUEUE *send_queue, EFLAG *send_flag, mempool_t *mempool, tree_t *device_tree,
                                 const void *const master_key, socket_ll *sockets, pthread_t *tid)
{

    pthread_t thread;

    PACKET_HANDLER_ARGS *handler_args = malloc(sizeof(PACKET_HANDLER_ARGS));
    if (handler_args == NULL) {
        log_error("[create_packet_handler_thread] malloc() failed allocating %d bytes for packet handler thread arguments | return 1",
            sizeof(PACKET_HANDLER_ARGS));
        return 1;
    }
    *args = handler_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        log_error("[create_packet_handler_thread] create_event_flag() failed | return 1");
        free(handler_args);
        return 1;
    }
    handler_args->signing_keys = sodium_malloc(sizeof(signing_key_pair_t));
    if (!(handler_args->signing_keys)) {
        log_error("[create_packet_handler_thread] sodium_malloc failed allocating %d bytes for sing keypair | return 1", sizeof(signing_key_pair_t));
        free(handler_args);
        return 1;
    }

    if (load_signing_key_pair(handler_args->signing_keys, master_key) != INDIGO_SUCCESS) {
        log_error("[create_packet_handler_thread] load_signing_key_pair() failed | return 1");
        free(handler_args);
        return 1;
    }

    handler_args->queue = queue;
    handler_args->send_queue = send_queue;
    handler_args->mempool = mempool;
    handler_args->wake = wake_mngr;
    handler_args->flag = flag;
    handler_args->device_tree = device_tree;
    handler_args->sockets = sockets;
    handler_args->send_flag = send_flag;
    handler_args->ui_queue = ui_queue;

    if (pthread_create(&thread, NULL, (void *)(&packet_handler_thread), handler_args)) {
        free_event_flag(flag);
        free(handler_args);
        log_error("[create_packet_handler_thread] pthread_create() failed to create packet handler thread | return 1 | errno %d", errno);
        return 1;
    }

    *tid = thread;
    return 0;
}
