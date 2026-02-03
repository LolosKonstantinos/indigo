//
// Created by Constantin on 26/01/2026.
//

#include <indigo_core/manager.h>
#include <crypto_utils.h>
#include <indigo_errors.h>
#include <indigo_types.h>
#include <hash_table.h>

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////
///
int *thread_manager_thread(MANAGER_ARGS *args) {
    //for the thread creation
    pthread_t tid_send = pthread_self();
    pthread_t tid_receive = pthread_self();
    pthread_t tid_update = pthread_self();
    pthread_t tid_handler = pthread_self();

    int *send_ret = NULL;
    int *receive_ret = NULL;
    int *update_ret = NULL;
    int *handler_ret = NULL;

    QUEUE *packet_queue = NULL;

    mempool_t *mempool = NULL; //the pool used for receiving
    mempool_attr pool_attr;

    //the thread args
    SEND_ARGS *send_args = NULL;
    RECV_ARGS *recv_args = NULL;
    INTERFACE_UPDATE_ARGS *update_args = NULL;
    PACKET_HANDLER_ARGS *handler_args = NULL;

    //for the event handling
    QNODE *qnode_pop = NULL;

    //the discovery sockets list
    SOCKET_LL *sockets = NULL;

    //the device tables
    hash_table_t *device_table;

    //the key pair
    SIGNING_KEY_PAIR *signing_key_pair = NULL;
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    //flags
    uint32_t flag_val;

    void *temp = NULL;

    int *process_return = NULL;
    int ret_val = 0; //general purpose return value variable

/*_________________________________________HERE STARTS THE FUNCTIONS LOGIC____________________________________________*/
    //allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        free(args);
        return NULL;
    }
    *process_return = 0;

    //prepare to create the threads

    //create the sockets
    sockets = malloc(sizeof(SOCKET_LL));
    if (sockets == NULL) {
        fprintf(stderr, "malloc() failed in discovery_manager_thread\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    pthread_mutex_init(&sockets->mutex, NULL);
    pthread_cond_init(&sockets->cond, NULL);
    sockets->head = NULL;

    temp = get_discovery_sockets(args->port, args->multicast_addr);
    if (temp == NULL) {
        fprintf(stderr, "Error in get_discovery_sockets\n");
        goto cleanup;
    }
    sockets->head = temp;

    //create the packet queue
    packet_queue = (QUEUE *)malloc(sizeof(QUEUE));
    if (packet_queue == NULL) {
        fprintf(stderr, "Failed to allocate memory for queue_receiving\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    if (init_queue(packet_queue)) {
        fprintf(stderr, "init_queue failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //create the memory pool
    pool_attr.dynamic_pool = 1;
    pool_attr.growth_factor = 1;
    //the initial mempool is about 1MiB, it may be extended automatically if needed
    mempool = new_mempool(1<<10, sizeof(packet_t) + sizeof(packet_info_t), &pool_attr);
    if (!mempool) {
        fprintf(stderr, "Failed to create mempool\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //the device table
    device_table = new_hash_table(sizeof(remote_device_t), crypto_sign_PUBLICKEYBYTES, 1<<4);
    if (!device_table) {
        fprintf(stderr, "Failed to create hash_table (device_table)\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //load the signing keys
    signing_key_pair = sodium_malloc(sizeof(SIGNING_KEY_PAIR));
    if (signing_key_pair == NULL) {
        fprintf(stderr, "Failed to load signing key pair\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    sodium_mprotect_readonly(args->master_key);
    ret_val = load_signing_key_pair(signing_key_pair, args->master_key);
    if (ret_val != INDIGO_SUCCESS) {
        sodium_mprotect_noaccess(args->master_key);
        fprintf(stderr, "Failed to load signing key pair\n");
        *process_return = ret_val;
        goto cleanup;
    }
    sodium_mprotect_noaccess(args->master_key);
    //the public key is our identifier and is used far more commonly than the private key
    //the less the time the private key is accessible the better
    memcpy(public_key, signing_key_pair->public, crypto_sign_PUBLICKEYBYTES);
    sodium_mprotect_noaccess(signing_key_pair);

    //create threads
    if (create_interface_updater_thread(&update_args,args->port, args->multicast_addr, args->flag, sockets, &tid_update)) {
        fprintf(stderr, "create_interface_updater_thread failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    if (create_packet_handler_thread(&handler_args, args->flag, packet_queue, mempool, args->master_key, &tid_handler)) {
        fprintf(stderr, "create_packet_handler_thread failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    if (create_receiving_thread(&recv_args, sockets, packet_queue, mempool, args->flag, &tid_receive)) {
        fprintf(stderr, "create_discovery_receiving_thread failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    if (create_discovery_sending_thread(&send_args, args->port, args->multicast_addr, sockets, args->flag, &tid_send, public_key)) {
        fprintf(stderr, "create_discovery_sending_thread failed\n");
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //the main loop
    while (!termination_is_on(args->flag)) {
        pthread_mutex_lock(&args->flag->mutex);
        pthread_cond_wait(&args->flag->cond, &args->flag->mutex);
        flag_val = args->flag->event_flag;
        pthread_mutex_unlock(&args->flag->mutex);

        if (termination_is_on(args->flag)) {
            *process_return = 0;
            break;
        }

        if (!(flag_val & EF_WAKE_MANAGER)){ continue;}

        //check the thread flags

        //check the interface updater thread
        flag_val = get_event_flag(update_args->flag);
        if (flag_val & EF_TERMINATION) {
            //for now, we terminate the whole operation, later we may pause or continue as we are
            goto cleanup;
        }
        if (flag_val & EF_INTERFACE_UPDATE) {
            printf("DEBUG: manager override\n");
            fflush(stdout);

            reset_single_event(update_args->flag, EF_INTERFACE_UPDATE);
            if (flag_val & EF_OVERRIDE_IO) {
                update_event_flag(send_args->flag, EF_OVERRIDE_IO);
                update_event_flag(recv_args->flag, EF_OVERRIDE_IO);
                update_event_flag(handler_args->flag, EF_OVERRIDE_IO);

                wait_on_flag_condition(update_args->flag, EF_OVERRIDE_IO, OFF);

                reset_single_event(send_args->flag, EF_OVERRIDE_IO);
                reset_single_event(recv_args->flag, EF_OVERRIDE_IO);
                reset_single_event(handler_args->flag, EF_OVERRIDE_IO);
            }
            printf("DEBUG: override complete\n");
            fflush(stdout);
        }

        //check the sending thread
        flag_val = get_event_flag(send_args->flag);
        if (flag_val & EF_TERMINATION) {
            //for now, we terminate the whole operation, later we may pause or continue as we are
            goto cleanup;
        }

        //check the receiving thread
        flag_val = get_event_flag(recv_args->flag);
        if (flag_val & EF_TERMINATION) {
            //for now, we terminate the whole operation, later we may pause or continue as we are
            goto cleanup;
        }
        //todo remove since the packet handler communicates directly with the receiver
        //in this case we just forward to the packet handler
        if (flag_val & EF_NEW_PACKET) {
            qnode_pop = queue_pop(packet_queue, QOPT_NON_BLOCK);
            if (qnode_pop != NULL) {
                if (queue_push(packet_queue,qnode_pop->data,qnode_pop->type)) {
                    destroy_qnode(qnode_pop);
                    goto cleanup;
                }
                destroy_qnode(qnode_pop);
                update_event_flag(handler_args->flag, EF_NEW_PACKET);
            }
        }


        //check the packet handler thread
        flag_val = get_event_flag(handler_args->flag);
        if (flag_val & EF_TERMINATION) {
            //for now, we terminate the whole operation, later we may pause or continue as we are
            goto cleanup;
        }
    }

    WSASetEvent(recv_args->termination_handle);
    WSASetEvent(update_args->termination_handle);

    set_event_flag(send_args->flag, EF_TERMINATION);
    set_event_flag(recv_args->flag, EF_TERMINATION);
    set_event_flag(handler_args->flag, EF_TERMINATION);
    set_event_flag(update_args->flag, EF_TERMINATION);

    if (pthread_equal(tid_send, pthread_self()) == 0) pthread_join(tid_send, (void **)&send_ret);
    if (pthread_equal(tid_receive, pthread_self()) == 0) pthread_join(tid_receive, (void **)&receive_ret);
    if (pthread_equal(tid_handler, pthread_self()) == 0) pthread_join(tid_handler, (void **)&handler_ret);
    if (pthread_equal(tid_update, pthread_self()) == 0) pthread_join(tid_update, (void **)&update_ret);

    free(send_ret);
    free(receive_ret);
    free(update_ret);
    free(handler_ret);


    //send args
    free_event_flag(send_args->flag);
    free(send_args);

    //receive args
    WSACloseEvent(recv_args->termination_handle);
    WSACloseEvent(recv_args->wake_handle);
    free_event_flag(recv_args->flag);
    free(recv_args);

    //update args
    WSACloseEvent(update_args->termination_handle);
    free_event_flag(update_args->flag);
    free(update_args);

    //handler args
    free_event_flag(handler_args->flag);
    free(handler_args);

    pthread_mutex_destroy(&sockets->mutex);
    pthread_cond_destroy(&sockets->cond);
    free_discv_sock_ll(sockets->head);

    destroy_queue(packet_queue);

    free_mempool(mempool);

    free(packet_queue);

    free_event_flag(args->flag);
    free(args);

    printf("DEBUG: manager thread exit\n");
    fflush(stdout);

    return process_return;

    cleanup:
    //signal termination to all threads
    if (recv_args != NULL) {
        WSASetEvent(recv_args->termination_handle);
    }
    if (update_args != NULL) {
        WSASetEvent(update_args->termination_handle);
    }

    if (send_args != NULL) set_event_flag(send_args->flag, EF_TERMINATION);
    if(recv_args != NULL)set_event_flag(recv_args->flag, EF_TERMINATION);
    if (handler_args != NULL) set_event_flag(handler_args->flag, EF_TERMINATION);
    if (update_args != NULL) set_event_flag(update_args->flag, EF_TERMINATION);

    //wait for the threads to terminate before we deallocate any resources
    if (pthread_equal(tid_send, pthread_self()) == 0) pthread_join(tid_send, (void **)&send_ret);
    if (pthread_equal(tid_receive, pthread_self()) == 0) pthread_join(tid_receive, (void **)&receive_ret);
    if (pthread_equal(tid_update, pthread_self()) == 0) pthread_join(tid_update, (void **)&update_ret);
    if (pthread_equal(tid_handler, pthread_self()) == 0) pthread_join(tid_handler, (void **)&handler_ret);

    free(send_ret);
    free(receive_ret);
    free(update_ret);
    free(handler_ret);

    //free the args of the threads
    //send
    if (pthread_equal(tid_send, pthread_self()) == 0) {
        free(send_args->flag);
        free(send_args);
    }
    //receive
    if (pthread_equal(tid_receive, pthread_self()) == 0) {
        WSACloseEvent(recv_args->termination_handle);
        WSACloseEvent(recv_args->wake_handle);
        free_event_flag(recv_args->flag);
        free(recv_args);
    }
    //updater
    if (pthread_equal(tid_update, pthread_self()) == 0) {
        WSACloseEvent(update_args->termination_handle);
        free_event_flag(update_args->flag);
        free(update_args);
    }
    //packet handler
    if (pthread_equal(tid_handler, pthread_self()) == 0) {
        free_event_flag(handler_args->flag);
        free(handler_args);
    }

    pthread_mutex_destroy(&sockets->mutex);
    pthread_cond_destroy(&sockets->cond);
    free_discv_sock_ll(sockets->head);

    destroy_queue(packet_queue);
    free(packet_queue);

    free(mempool);

    free_event_flag(args->flag);
    free(args);
    sodium_free(signing_key_pair);
    printf("DEBUG: manager thread exit\n");
    fflush(stdout);
    return process_return;

}

///////////////////////////////////////////////////////////////////
///                                                             ///
///                  THREAD_CREATING_FUNCTIONS                  ///
///                                                             ///
///////////////////////////////////////////////////////////////////


int cancel_device_discovery(pthread_t tid, EFLAG *flag) {
    int *ret = NULL, val;

    set_event_flag(flag, EF_TERMINATION | EF_WAKE_MANAGER);

    if (pthread_equal(tid,pthread_self()) == 0) {
        pthread_join(tid,(void **)&ret);
    }
    printf("DEBUG: manager thread joined\n");
    fflush(stdout);

    if (ret == NULL) return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    val = *ret;
    free(ret);
    return val;
}

int create_thread_manager_thread(MANAGER_ARGS **args, const int port, const uint32_t multicast_address, pthread_t *tid){
    pthread_t thread;

    MANAGER_ARGS *manager_args = malloc(sizeof(MANAGER_ARGS));
    if (manager_args == NULL) {
        fprintf(stderr, "Error allocating memory for MANAGER_ARGS\n");
        return 1;
    }
    *args = manager_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_discovery_sending_thread\n");
        free(manager_args);
        return 1;
    }

    manager_args->flag = flag;
    manager_args->port = port;
    manager_args->multicast_addr = multicast_address;

    if (pthread_create(&thread, NULL, (void *)(&thread_manager_thread), manager_args)) {
        free_event_flag(flag);
        free(*args);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_discovery_sending_thread(SEND_ARGS **args, int port, uint32_t multicast_address, SOCKET_LL *sockets, EFLAG *wake_mngr, pthread_t *tid, unsigned
                                    char public_key[crypto_sign_PUBLICKEYBYTES]){
    pthread_t thread;

    SEND_ARGS *send_args = malloc(sizeof(SEND_ARGS));
    if (send_args == NULL) {
        fprintf(stderr, "malloc() failed in create_discovery_sending_thread\n");
        return 1;
    }
    *args = send_args;


    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_discovery_sending_thread\n");
        free(send_args);
        return 1;
    }

    send_args->port = port;
    send_args->multicast_addr = multicast_address;
    send_args->sockets = sockets;
    send_args->wake = wake_mngr;
    send_args->flag = flag;
    memcpy(send_args->public_key, public_key, crypto_sign_PUBLICKEYBYTES);

    if (pthread_create(&thread, NULL, (void *)(&send_discovery_thread), send_args)) {
        free_event_flag(flag);
        free(args);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_receiving_thread(
    RECV_ARGS **args, SOCKET_LL *sockets, QUEUE *queue, mempool_t* mempool, EFLAG *wake_mngr, pthread_t *tid){

    pthread_t thread;

    RECV_ARGS *recv_args = malloc(sizeof(RECV_ARGS));
    if (recv_args == NULL) {
        fprintf(stderr, "malloc() failed in create_discovery_sending_thread\n");
        return 1;
    }
    *args = recv_args;


    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_discovery_sending_thread\n");
        free(recv_args);
        return 1;
    }


    recv_args->wake_handle = WSACreateEvent();
    if (recv_args->wake_handle == NULL) {
        fprintf(stderr, "WSACreateEvent() failed in create_discovery_sending_thread\n");
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
    }

    recv_args->queue = queue;
    recv_args->mempool = mempool;
    recv_args->sockets = sockets;
    recv_args->wake = wake_mngr;
    recv_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&recv_discovery_thread), recv_args)) {
        free_event_flag(flag);
        free(recv_args);
        return 1;
    }

    *tid = thread;

    return 0;
}

int create_interface_updater_thread(INTERFACE_UPDATE_ARGS **args, int port, uint32_t multicast_address, EFLAG *wake_mngr, SOCKET_LL *sockets, pthread_t *tid){
    pthread_t thread;

    INTERFACE_UPDATE_ARGS *update_args = malloc(sizeof(INTERFACE_UPDATE_ARGS));
    if (update_args == NULL) {
        fprintf(stderr, "malloc() failed in create_interface_updater_thread\n");
        return 1;
    }
    *args = update_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_interface_updater_thread\n");
        free(update_args);
        return 1;
    }

    update_args->termination_handle = WSACreateEvent();
    if (update_args->termination_handle == NULL) {
        fprintf(stderr, "WSACreateEvent() failed in create_interface_updater_thread\n");
        free_event_flag(flag);
        free(update_args);
        return 1;
    }

    update_args->port = port;
    update_args->multicast_addr = multicast_address;
    update_args->sockets = sockets;
    update_args->wake = wake_mngr;
    update_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&interface_updater_thread), update_args)) {
        free_event_flag(flag);
        free(update_args);
        return 1;
    }

    *tid = thread;
    return 0;
}

int create_packet_handler_thread(
    PACKET_HANDLER_ARGS **args, EFLAG *wake_mngr, QUEUE *queue, mempool_t* mempool, const void*
    const master_key, pthread_t *tid){

    pthread_t thread;

    PACKET_HANDLER_ARGS *handler_args = malloc(sizeof(INTERFACE_UPDATE_ARGS));
    if (handler_args == NULL) {
        fprintf(stderr, "malloc() failed in create_interface_updater_thread\n");
        return 1;
    }
    *args = handler_args;

    EFLAG *flag = create_event_flag();
    if (flag == NULL) {
        fprintf(stderr,"create_event_flag() failed in create_interface_updater_thread\n");
        free(handler_args);
        return 1;
    }
    handler_args->signing_keys = sodium_malloc(sizeof(SIGNING_KEY_PAIR));
    if (!(handler_args->signing_keys)) {
        fprintf(stderr, "malloc() failed in create_interface_updater_thread\n");
        free(handler_args);
        return 1;
    }

    if (load_signing_key_pair(handler_args->signing_keys, master_key) != INDIGO_SUCCESS) {
        fprintf(stderr,"load_signing_key_pair() failed in create_interface_updater_thread\n");
        free(handler_args);
        return 1;
    }
    sodium_mprotect_noaccess(handler_args->signing_keys);

    handler_args->queue = queue;
    handler_args->mempool = mempool;
    handler_args->wake = wake_mngr;
    handler_args->flag = flag;

    if (pthread_create(&thread, NULL, (void *)(&packet_handler_thread), handler_args)) {
        free_event_flag(flag);
        free(handler_args);
        return 1;
    }

    *tid = thread;
    return 0;
}
