//
// Created by Constantin on 26/01/2026.
//

#include <indigo_core/packet_handler.h>
#include <indigo_errors.h>
#include <Queue.h>
#include <math.h>

#include "indigo_types.h"

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////
//todo: check for io override, we need to invalidate saved sockets, create mechanism to update sockets
//todo: search in the tree works by providing a struct of the data with the fields that act as a key initialized
//todo: i dont think we need mac addresses, as for now we just send the arp and do nothing with the mac, remove mac
int *packet_handler_thread(PACKET_HANDLER_ARGS *args) {
    uint32_t flag_val = 0;
    QNODE *node = NULL;

    void *mac_address = NULL;
    ULONG mac_address_len = 0;
    PULONG p_mac_address_len = &mac_address_len;

    time_t curr_time = 0;
    struct timespec timespec;
    time_t lowest_time = 0;
    time_t time_diff = 0;

    unsigned char iterations_until_cleanup = 10;

    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char signed_nonce[crypto_sign_BYTES + INDIGO_NONCE_SIZE];

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];

    packet_t *packet = NULL;
    packet_info_t* packet_info = NULL;
    PACKET_HEADER packet_header;
    remote_device_t rdev;
    remote_device_t *found_rdev = NULL;

    //the expected signing response table
    tree_t *xsr_tree = NULL;
    xsr_t xsr;
    xsr_t *found_xsr = NULL;

    //the expected file packet table
    tree_t *xfp_tree = NULL;
    xfp_t xfp;
    xfp_t *found_xfp = NULL;

    file_sending_request_fwd_t *fwd;

    session_t *session = NULL;
    unsigned char *session_pk;
    unsigned char *session_sk;

    active_file_t *tmp_active_file;

    FILE *recent_files[2]; //an array of the last 2 file descriptors used
    FILE *tmp_file;
    int ret = 0; //general purpose return variable


    int *process_return = NULL;

    //allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;

    //the less the private key is exposed the better, we copy the public key since it is frequently used

    memcpy(public_key, args->signing_keys->public, crypto_sign_PUBLICKEYBYTES);

    //create the expected packet table
    ret = new_tree(&xsr_tree, cmp_xsr, sizeof(xsr_t), BINARY_TREE_TYPE_AVL);
    if (!ret) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        return process_return;
    }
    ret = new_tree(&xfp_tree, cmp_xfp, sizeof(xfp_t), BINARY_TREE_TYPE_AVL);
    if (!ret) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        return process_return;
    }

    //the main loop
    while (!termination_is_on(args->flag)) {
        ///////////////////////////////////
        ///  phase 1: check for events  ///
        ///////////////////////////////////

        flag_val = get_event_flag(args->flag);
        if (flag_val & EF_TERMINATION) {
            break;
        }

        if (flag_val & EF_NEW_PACKET) {
            reset_single_event(args->flag, EF_NEW_PACKET);

            node = queue_pop(args->queue,QOPT_NON_BLOCK);

            if (node == NULL) {continue;}

            if (node->type == QET_NEW_PACKET) {
                //extract the contents of the node
                packet = node->data;
                packet_info = node->data + sizeof(packet_t);

                destroy_qnode(node);

                memcpy(&packet_header, packet, sizeof(packet_header));
                //prepare the remote device struct to fill with the remote device info
                //we zero so that previous garbage doesn't affect the new device (e.g. if the new mac address is smaller)
                memset(&rdev, 0, sizeof(remote_device_t));
                //most of the time we need to search the tree so we just copy it from the start
                memcpy(rdev.peer_public_key, packet->id, crypto_sign_PUBLICKEYBYTES);

                //todo handle all types of packets
                switch (packet_header.pac_type) {
                    //todo: later every packet will contain the current time +- 3 seconds signed
                    //todo: we will need to check that too (later, once implemented on the send level)
                case MSG_INIT_PACKET:
                    mac_address_len = 6;
                    mac_address = calloc(1, mac_address_len);
                    if (mac_address == NULL) {
                        fprintf(stderr, "malloc() failed in device_discovery_receiving\n");
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        free_tree(xsr_tree);
                        free_tree(xfp_tree);
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        return process_return;
                    }

                    if (SendARP(packet_info->address.sin_addr.S_un.S_addr,INADDR_ANY, mac_address, p_mac_address_len)
                        != NO_ERROR) {
                        //todo: i dont think this should return,
                        //todo: error check and either proceed or return if it is a network error
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free(mac_address);
                        free_tree(xsr_tree);
                        free_tree(xfp_tree);
                        return process_return;
                        }

                    memcpy(rdev.mac_addr, mac_address, mac_address_len);
                    //todo: if we actually need the length of the mac we should do it here

                    free(mac_address);
                    //search in the tree
                    ret = args->device_tree->search_pin(args->device_tree, &rdev, &found_rdev);

                    if (ret == 0) {
                        //the search function returns a copy of the data
                        found_rdev->expiration_time = time(NULL); //renew the timestamp
                        args->device_tree->search_release(args->device_tree);
                        break;
                    }
                    args->device_tree->search_release(args->device_tree);

                    //the remote device is not on the table so we add it
                    rdev.expiration_time = time(NULL);
                    rdev.socket = packet_info->socket;
                    rdev.ip = packet_info->address.sin_addr.S_un.S_addr;
                    rdev.dev_state_flag = RDSF_UNVERIFIED; //the device is not verified

                    args->device_tree->insert(args->device_tree, &rdev);

                    //send signing request
                    randombytes_buf(nonce,INDIGO_NONCE_SIZE);
                    build_packet(packet,MSG_SIGNING_REQUEST,public_key,nonce);
                    send_packet((int)htonl(PORT),packet_info->address.sin_addr.S_un.S_addr,
                                packet_info->socket,packet, args->flag);

                    //add signing response to expected packets
                    xsr.expiration_time = time(NULL) + EXPIRATION_TIME;
                    memcpy(xsr.nonce, nonce, INDIGO_NONCE_SIZE);

                    if (xsr_tree->insert(xsr_tree, &xsr)) {
                        //todo: what do we do if insert fails (either the id is already in the tree or memory error
                    }

                    break;
                case MSG_SIGNING_REQUEST:
                    //sign the nonce and send the signature with the public key and a new nonce
                    if (sign_buffer(args->signing_keys,packet->data, INDIGO_NONCE_SIZE,signed_nonce,NULL)) {
                        //todo: IDK do something
                        break;
                    }
                    build_packet(packet, MSG_SIGNING_RESPONSE, public_key, NULL);

                    memcpy(packet->data, signed_nonce, sizeof(signed_nonce));

                    //if the peer is verified we don't need to send a signing request
                    ret = args->device_tree->search(args->device_tree, &rdev);
                    if (ret == 0) {
                        if (rdev.dev_state_flag == RDSF_UNVERIFIED) {
                            randombytes_buf(nonce,INDIGO_NONCE_SIZE);
                            memcpy(packet->data + sizeof(signed_nonce)
                                , nonce
                                , INDIGO_NONCE_SIZE);
                            send_packet((int)htonl(PORT),packet_info->address.sin_addr.S_un.S_addr
                                ,packet_info->socket
                                ,packet,args->flag);
                        }
                    }
                    //in this case they found us before we received their discovery packet (if they sent any)
                    else {
                        //add the device to the device table
                        //we detected the device (though it is unverified)
                        rdev.expiration_time = time(NULL);
                        rdev.socket = packet_info->socket;
                        rdev.ip = packet_info->address.sin_addr.S_un.S_addr;
                        memcpy(rdev.peer_public_key, packet->id, crypto_sign_PUBLICKEYBYTES);
                        rdev.dev_state_flag = RDSF_UNVERIFIED; //the device is not verified

                        //add signing response to expected packets
                        xsr.expiration_time = time(NULL) + EXPIRATION_TIME;
                        memcpy(xsr.nonce, nonce, INDIGO_NONCE_SIZE);

                        if (xsr_tree->insert(xsr_tree, &xsr)) {
                            //todo: what do we do if insert fails (either the id is already in the table or memory error
                        }
                    }
                    break;

                case MSG_SIGNING_RESPONSE:
                    //here the key is the id (public key) no need to use a xsr_key_t for the comparison
                    memcpy(xsr.id, packet->id, crypto_sign_PUBLICKEYBYTES);
                    ret = xsr_tree->search(xsr_tree, &xsr);
                    if (ret == 0) {
                        ret = crypto_sign_open(nonce,NULL,
                            packet->data,
                            INDIGO_NONCE_SIZE + crypto_sign_BYTES,
                            packet->id);
                        if (ret == 0) {
                            //if the nonce signed is the same as the one we sent to be signed
                            if (memcmp(xsr.nonce, nonce,INDIGO_NONCE_SIZE) == 0) {
                                //the device is got verified

                                //remove the expected packet
                                xsr_tree->remove(xsr_tree, &xsr);

                                ret = args->device_tree->search_pin(args->device_tree, &rdev, &found_rdev);
                                //I am not sure how we could get an expected packet for a device
                                //that isn't in the device table
                                if (ret == 0) {
                                    found_rdev->expiration_time = time(NULL);
                                    found_rdev->dev_state_flag |= RDSF_VERIFIED;
                                    args->device_tree->search_release(args->device_tree);
                                    break;
                                }
                                args->device_tree->search_release(args->device_tree);
                            }
                        }
                    }

                    //there was either an error or the device is not legitimate
                    //therefore we send an error message
                    build_packet(packet, MSG_ERR, public_key, NULL);
                    send_packet((int)htonl(PORT)
                                ,packet_info->address.sin_addr.S_un.S_addr
                                ,packet_info->socket
                                ,packet,args->flag);

                    //todo better send error message, track the failed attempts and then ban
                    break;
                case MSG_FILE_SENDING_REQUEST:{
                        //we need permission to proceed, so we push it to the manager to handle
                        //tell the interface (cli or gui via queue), the interface will ask the user
                        //if the user agrees, we create one time session keys, send them our one time public key
                        //if it gets accepted we receive a session_t struct via queue, and store an expected file packet
                        file_sending_request_fwd_t *fsr;
                        fsr = malloc(sizeof(file_sending_request_fwd_t));
                        if (!fsr) {
                            set_event_flag(args->flag, EF_TERMINATION);
                            set_event_flag(args->wake, EF_WAKE_MANAGER);
                            free_tree(xsr_tree);
                            free_tree(xfp_tree);
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            return process_return;
                        }
                        memcpy(fsr->id, packet->id, crypto_sign_PUBLICKEYBYTES);
                        memcpy(fsr->key, packet->data, crypto_kx_PUBLICKEYBYTES);
                        memcpy(&(fsr->file_size), packet->data + crypto_kx_PUBLICKEYBYTES, sizeof(size_t));
                        wcsncpy(fsr->file_name
                            ,(wchar_t *)(packet->data + crypto_kx_PUBLICKEYBYTES + sizeof(size_t))
                            ,MAX_PATH);
                        fsr->file_name[MAX_PATH - 1] = L'\0';

                        if (queue_push(args->cli_queue, fsr, QET_FILE_SENDING_REQUEST)) {
                            set_event_flag(args->flag, EF_TERMINATION);
                            set_event_flag(args->wake, EF_WAKE_MANAGER);
                            free_tree(xsr_tree);
                            free_tree(xfp_tree);
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            return process_return;
                        }
                        break;
                }
                case MSG_FILE_SENDING_RESPONSE:
                    //todo: probably check a tree to see if we sent any send request
                    //we got their one time public key, and confirmation to proceed
                    //we calculate the send key
                    //tell the manager or the sending thread to start sending the file

                    memcpy(&(xfp.session_id.pk), packet->id, crypto_sign_PUBLICKEYBYTES);
                    xfp.session_id.serial = 0;
                    ret = xfp_tree->search(xfp_tree, &xfp);
                    if (ret != 0) break;

                    //necessary allocations
                    tmp_active_file = malloc(sizeof(active_file_t));
                    session = malloc(sizeof(session_t));
                    session_pk = malloc(crypto_kx_PUBLICKEYBYTES);
                    session_sk = sodium_malloc(crypto_kx_SECRETKEYBYTES);
                    if (!session || !session_sk || !session_pk || !tmp_active_file) {
                        free(tmp_active_file);
                        free(session);
                        free(session_pk);
                        sodium_free(session_sk);
                        free_tree(xsr_tree);
                        free_tree(xfp_tree);
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        return process_return;
                    }
                    session->receive_key = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
                    session->transmit_key = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
                    if (!session->receive_key || !session->transmit_key) {
                        free(tmp_active_file);
                        sodium_free(session->receive_key);
                        sodium_free(session->transmit_key);
                        free(session);
                        free(session_pk);
                        sodium_free(session_sk);
                        free_tree(xsr_tree);
                        free_tree(xfp_tree);
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        return process_return;
                    }

                    //create the session keys
                    crypto_kx_keypair(session_pk,session_sk);
                    sodium_mprotect_readonly(session_sk);
                    ret = crypto_kx_client_session_keys(session->receive_key,
                        session->transmit_key,
                        session_pk,
                        session_sk,
                        packet->data);
                    sodium_mprotect_readonly(session->receive_key);
                    sodium_mprotect_readonly(session->transmit_key);

                    if (ret) {
                        //the peer key is invalid, we reject the session
                        queue_push(args->cli_queue,fwd,QET_SESSION_REJECTED);

                        sodium_free(session->receive_key);
                        sodium_free(session->transmit_key);
                        free(session);
                    }
                    else {
                        memcpy(&(session->session_id), &(xfp.session_id), sizeof(session_id_t));
                        session->bytes_moved = 0;
                        session->start_time = time(NULL);
                        session->status_flags = 0;
                        session->port = htons(PORT);
                        session->socket = packet_info->socket;
                        session->ip = packet_info->address.sin_addr.S_un.S_addr;

                        args->session_tree->insert(args->session_tree,session);

                        tmp_active_file->fd = xfp.file;
                        tmp_active_file->next_chunk = 0;
                        tmp_active_file->next = NULL;

                        ret = queue_push(args->send_queue, tmp_active_file,QET_SEND_FILE);
                        if (ret != 0) {
                            free(tmp_active_file);
                            free(session_pk);
                            sodium_free(session_sk);
                            free_tree(xsr_tree);
                            free_tree(xfp_tree);
                            set_event_flag(args->flag, EF_TERMINATION);
                            set_event_flag(args->wake, EF_WAKE_MANAGER);
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            return process_return;
                        }
                    }

                    sodium_memzero(session_pk, crypto_kx_PUBLICKEYBYTES);
                    free(session_pk);
                    sodium_free(session_sk);//zeroes and then frees
                    destroy_qnode(node);
                    break;
                case MSG_RESEND:
                case MSG_FILE_CHUNK:
                case MSG_STOP_FILE_TRANSMISSION:
                case MSG_PAUSE_FILE_TRANSMISSION:
                case MSG_CONTINUE_FILE_TRANSMISSION:
                case MSG_ERR:
                default:
                    printf("oops...");
                    break;
                }

                //we no longer need the packet
                args->mempool->free(args->mempool,packet);
                packet = NULL;
                packet_info = NULL;
            }
            else if (node->type == QET_SESSION_START) {
                fwd = node->data;

                //necessary allocations
                packet = malloc(sizeof(struct udp_packet_t));
                session = malloc(sizeof(session_t));
                session_pk = malloc(crypto_kx_PUBLICKEYBYTES);
                session_sk = sodium_malloc(crypto_kx_SECRETKEYBYTES);
                if (!session || !session_sk || !session_pk || !packet) {
                    free(packet);
                    free(session);
                    free(session_pk);
                    sodium_free(session_sk);
                    free_tree(xsr_tree);
                    free_tree(xfp_tree);
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    return process_return;
                }
                session->receive_key = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
                session->transmit_key = sodium_malloc(crypto_kx_SESSIONKEYBYTES);
                if (!session->receive_key || !session->transmit_key) {
                    sodium_free(session->receive_key);
                    sodium_free(session->transmit_key);
                    free(packet);
                    free(session);
                    free(session_pk);
                    sodium_free(session_sk);
                    free_tree(xsr_tree);
                    free_tree(xfp_tree);
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    return process_return;
                }
                xfp.file = tmpfile();
                if (!xfp.file) {
                    sodium_free(session->receive_key);
                    sodium_free(session->transmit_key);
                    free(packet);
                    free(session);
                    free(session_pk);
                    sodium_free(session_sk);
                    free_tree(xsr_tree);
                    free_tree(xfp_tree);
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_CAN_NOT_OPEN_FILE;
                    return process_return;
                }
                //create the session keys
                crypto_kx_keypair(session_pk,session_sk);
                sodium_mprotect_readonly(session_sk);
                ret = crypto_kx_server_session_keys(session->receive_key,
                    session->transmit_key,
                    session_pk,
                    session_sk,
                    fwd->key);
                sodium_mprotect_readonly(session->receive_key);
                sodium_mprotect_readonly(session->transmit_key);

                if (ret) {
                    //the peer key is invalid, we reject the session
                    queue_push(args->cli_queue,fwd,QET_SESSION_REJECTED);

                    sodium_free(session->receive_key);
                    sodium_free(session->transmit_key);
                    free(packet);
                    free(session);
                    free(session_pk);
                    sodium_free(session_sk);
                }
                else {
                    //send public key to peer
                    build_packet(packet, MSG_FILE_SENDING_RESPONSE,public_key,session_pk);
                    ret = send_packet(fwd->port,fwd->addr,fwd->socket,packet,args->flag);
                    if (ret) {
                        //todo, idk handle the error
                    }
                    free(packet);
                    //create expected file packets
                    xfp.expiration_time = time(NULL) + EXPIRATION_TIME;
                    xfp.packet_number = (uint64_t)ceil((double)(fwd->file_size)/(double)10);
                    xfp.session_id.serial = 0; //todo: assign the smallest valid serial number
                    xfp.receive_key = session->receive_key;
                    memcpy(xfp.session_id.pk,fwd->id,crypto_sign_PUBLICKEYBYTES);

                    xfp_tree->insert(xfp_tree,&xfp);

                    memcpy(&(session->session_id), &(xfp.session_id), sizeof(session_id_t));
                    session->bytes_moved = 0;
                    session->start_time = time(NULL);
                    session->status_flags = 0;
                    session->port = fwd->port;
                    session->socket = fwd->socket;
                    session->ip = fwd->addr;

                    args->session_tree->insert(args->session_tree,session);
                    free(fwd);
                }

                sodium_memzero(session_pk, crypto_kx_PUBLICKEYBYTES);
                free(session_pk);
                sodium_free(session_sk);//zeroes and then frees
                destroy_qnode(node);
            }
            else if (node->type == QET_EXPECT_SEND_RESPONSE) {
                //todo: put an xfp for the response we expect for the file we will send
                free(node->data);
                destroy_qnode(node);
            }
            else {
                //probably an error but good to check
                destroy_qnode(node);
                continue;
            }
            //todo this code only runs when we get a new packet to process, is this code supposed to run in every cycle?
            //here if there are more packets in the queue we go back up to process them,
            //but we don't want to have ghost devises,
            //so in case there are too many packets we refresh the list once per 10 packets processed
            if (iterations_until_cleanup > 0) {
                iterations_until_cleanup--;
                if (!queue_is_empty(args->queue)) continue;
            }
            else {iterations_until_cleanup = 10;}

            /////////////////////////////////////////
            ///  phase 2: update the device list  ///
            /////////////////////////////////////////

            //todo: keep a linked list of all devices, as IDs, and check if there are devices to be removed
            //todo: calculate the max sleep time we can get if the queue is empty

            //there is no need to sleep if there is more stuff to do
            if (!queue_is_empty(args->queue)) continue;

            /////////////////////////////////////////////
            ///  phase 3: wait a little and go again  ///
            /////////////////////////////////////////////
            clock_gettime(CLOCK_REALTIME,&timespec);
            timespec.tv_sec +=lowest_time;

            pthread_mutex_lock(&args->flag->mutex);
            pthread_cond_timedwait(&args->flag->cond,&args->flag->mutex,&timespec);
            pthread_mutex_unlock(&args->flag->mutex);

        }
    }
    free_tree(xsr_tree);
    free_tree(xfp_tree);
    return process_return;
}

//cmp functions (helpers)
int cmp_xsr(void *s1, void *s2) {
    return memcmp(((xsr_t *)s1)->id, ((xsr_t *)s2)->id, crypto_kx_PUBLICKEYBYTES);
}

int cmp_xfp(void *s1, void *s2) {
    return memcmp(&((xfp_t *)s1)->session_id, &((xfp_t *)s2)->session_id, (sizeof(uint64_t) + crypto_sign_PUBLICKEYBYTES));
}