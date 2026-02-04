//
// Created by Constantin on 26/01/2026.
//

#include <indigo_core/packet_handler.h>
#include <indigo_errors.h>
#include <Queue.h>
#include "indigo_types.h"

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////
//todo: re-write the packet handler, we need to handle every type of packet
//todo: structure the xpacket table keys so that an rdev can have multiple expected packets
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

    hash_table_t *xpack_table = NULL; // the expected packet table
    expected_packet_t xpacket;
    expected_packet_t *found_xpacket = NULL;

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
    xpack_table = new_hash_table(sizeof(expected_packet_t), crypto_sign_PUBLICKEYBYTES, 1<<6);
    if (xpack_table == NULL) {
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

            if (node->type != QET_NEW_PACKET) {
                //probably an error but good to check
                destroy_qnode(node);
                continue;
            }

            //extract the contents of the node
            packet = node->data;
            packet_info = node->data + sizeof(packet_t);

            destroy_qnode(node);

            memcpy(&packet_header, packet, sizeof(packet_header));
            //prepare the remote device struct to fill with the remote device info
            //we zero so that previous garbage doesn't affect the new device (e.g. if the new mac address is smaller)
            memset(&rdev, 0, sizeof(remote_device_t));

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
                        delete_hash_table(xpack_table);
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
                        delete_hash_table(xpack_table);
                        return process_return;
                        }

                    memcpy(rdev.mac_addr, mac_address, mac_address_len);
                    //todo: if we actually need the length of the mac we should do it here

                    free(mac_address);

                    found_rdev = args->device_table->search(args->device_table, packet->id);

                    if (found_rdev != NULL) {
                        found_rdev->expiration_time = time(NULL); //renew the timestamp
                        continue;
                    }
                    //the remote device is not on the table so we add it
                    rdev.expiration_time = time(NULL);
                    rdev.socket = packet_info->socket;
                    rdev.ip = packet_info->address.sin_addr.S_un.S_addr;
                    memcpy(rdev.peer_public_key, packet->id, crypto_sign_PUBLICKEYBYTES);
                    rdev.dev_state_flag = RDSF_UNVERIFIED; //the device is not verified

                    args->device_table->insert(args->device_table, packet->id, &rdev);

                    //send signing request
                    randombytes_buf(nonce,INDIGO_NONCE_SIZE);
                    build_packet(packet,MSG_SIGNING_REQUEST,public_key,nonce);
                    send_packet((int)htonl(PORT),packet_info->address.sin_addr.S_un.S_addr,
                                packet_info->socket,packet, args->flag);

                    //add signing response to expected packets
                    xpacket.expiration_time = time(NULL) + EXPIRATION_TIME;
                    xpacket.type = MSG_SIGNING_RESPONSE;
                    memcpy(xpacket.id, packet->id, crypto_sign_PUBLICKEYBYTES);
                    memcpy(xpacket.nonce, nonce, INDIGO_NONCE_SIZE);
                    memset(xpacket.serial_number_range,0,sizeof(xpacket.serial_number_range));
                    memset(xpacket.zero, 0, sizeof(xpacket.zero));

                    if (xpack_table->insert(xpack_table, xpacket.id, &xpacket)) {
                        //todo: what do we do if insert fails (either the id is already in the table or memory error
                    }

                    break;
                case MSG_SIGNING_REQUEST:
                    //sign the nonce and send the signature with the public key and a new nonce
                    if (sign_buffer(args->signing_keys,packet->data, INDIGO_NONCE_SIZE,signed_nonce,NULL)) {
                        //todo: IDK do something
                        continue;
                    }
                    build_packet(packet, MSG_SIGNING_RESPONSE, public_key, NULL);

                    memcpy(packet->data, signed_nonce, sizeof(signed_nonce));

                    memcpy(packet->data + sizeof(signed_nonce), public_key, crypto_sign_PUBLICKEYBYTES);

                    //if the peer is verified we don't need to send a signing request
                    found_rdev = args->device_table->search(args->device_table, packet->id);
                    if (found_rdev != NULL) {
                        if (found_rdev->dev_state_flag == RDSF_UNVERIFIED) {
                            randombytes_buf(nonce,INDIGO_NONCE_SIZE);
                            memcpy(packet->data + sizeof(signed_nonce) + crypto_sign_PUBLICKEYBYTES,nonce
                                , INDIGO_NONCE_SIZE);
                            send_packet((int)htonl(PORT),packet_info->address.sin_addr.S_un.S_addr
                                ,packet_info->socket
                                ,packet,args->flag);
                        }
                    }
                //in this case they found us before we received their discovery packet (if they sent any)
                    else {
                        //the remote device is not on the table so we add it
                        rdev.expiration_time = time(NULL);
                        rdev.socket = packet_info->socket;
                        rdev.ip = packet_info->address.sin_addr.S_un.S_addr;
                        memcpy(rdev.peer_public_key, packet->id, crypto_sign_PUBLICKEYBYTES);
                        rdev.dev_state_flag = RDSF_UNVERIFIED; //the device is not verified

                        args->device_table->insert(args->device_table, packet->id, &rdev);

                        //add signing response to expected packets
                        xpacket.expiration_time = time(NULL) + EXPIRATION_TIME;
                        xpacket.type = MSG_SIGNING_RESPONSE;
                        memcpy(xpacket.id, packet->id, crypto_sign_PUBLICKEYBYTES);
                        memcpy(xpacket.nonce, nonce, INDIGO_NONCE_SIZE);
                        memset(xpacket.serial_number_range,0,sizeof(xpacket.serial_number_range));
                        memset(xpacket.zero, 0, sizeof(xpacket.zero));

                        if (xpack_table->insert(xpack_table, xpacket.id, &xpacket)) {
                            //todo: what do we do if insert fails (either the id is already in the table or memory error
                        }
                    }
                    break;

                case MSG_SIGNING_RESPONSE:
                    found_xpacket = xpack_table->search(xpack_table, packet->id);
                    if (found_xpacket != NULL) {
                        if (found_xpacket->type == MSG_SIGNING_RESPONSE) {
                            ret = crypto_sign_open(nonce,NULL,
                                packet->data,
                                INDIGO_NONCE_SIZE + crypto_sign_BYTES,
                                packet->id);
                            if (ret == 0) {
                                //if the nonce signed is the same as the one we sent to be signed
                                if (memcmp(found_xpacket->nonce, nonce,INDIGO_NONCE_SIZE) == 0) {
                                    //the device is got verified
                                    found_rdev = args->device_table->search(args->device_table, packet->id);
                                    //I am not sure how we could get an expected packet for a device
                                    //that isn't in the device table
                                    if (found_rdev != NULL) {
                                        found_rdev->expiration_time = time(NULL);
                                        found_rdev->dev_state_flag |= RDSF_VERIFIED;
                                        break;
                                    }
                                }
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
                        //tell the manager (via queue), the manager will ask the user
                        //if the user agrees, we create one time session keys, send them our one time public key
                        file_sending_request_fwd_t *fsr;
                        fsr = malloc(sizeof(file_sending_request_fwd_t));
                        if (!fsr) {
                            delete_hash_table(xpack_table);
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            return process_return;
                        }
                        memcpy(fsr->id, packet->id, crypto_sign_PUBLICKEYBYTES);
                        memcpy(fsr->key, packet->data, crypto_kx_PUBLICKEYBYTES);
                        wcscpy_s(fsr->file_name, MAX_PATH * sizeof(wchar_t),(wchar_t *)(packet->data + crypto_kx_PUBLICKEYBYTES));

                        if (queue_push(args->queue, fsr, QET_FILE_SENDING_REQUEST)) {
                            delete_hash_table(xpack_table);
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            return process_return;
                        }
                        break;
                    }
                case MSG_FILE_SENDING_RESPONSE:
                    //TODO
                    //we got their one time public key, and confirmation to proceed
                    //we calculate the send key
                    //tell the manager or the sending thread to start sending the file
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

            //here if there are more packets in the queue we go back up to process them,
            //but we don't want to have ghost devises,
            //so in case there are too many packets we refresh the list once per 10 packets processed
            if (iterations_until_cleanup > 0) {
                iterations_until_cleanup--;
                if (!queue_is_empty(args->queue)) {continue;}
            }
            else {iterations_until_cleanup = 10;}

            /////////////////////////////////////////
            ///  phase 2: update the device list  ///
            /////////////////////////////////////////

            //todo: keep a linked list of all devices, as IDs, and check if there are devices to be removed
            //todo: calculate the max sleep time we can get if the queue is empty

            //there is no need to sleep if there is more stuff to do
            if (!queue_is_empty(args->queue)) {continue;}

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
        return process_return;
}