//
// Created by Constantin on 26/01/2026.
//

#include <indigo_core/packet_handler.h>
#include <indigo_errors.h>
//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////
//todo: re-write the packet handler, we need to handle every type of packet
int *packet_handler_thread(PACKET_HANDLER_ARGS *args) {
    uint32_t flag_val = 0;
    QNODE *node;

    void *mac_address = NULL;
    ULONG mac_address_len = 0;
    PULONG p_mac_address_len = &mac_address_len;

    time_t curr_time;
    struct timespec ts;
    time_t lowest_time = 0, time_diff;

    unsigned char iterations_until_cleanup = 10;

    unsigned char nonce[INDIGO_NONCE_SIZE];
    unsigned char signed_nonce[crypto_sign_BYTES + INDIGO_NONCE_SIZE];


    PACKET_NODE *temp_dev, *found_dev;
    PACKET_INFO* packet_info;
    PACKET *packet;
    PACKET_HEADER packet_header;

    int ret = 0; //general purpose return variable


    int *process_return = NULL;

    //allocate memory for the return value
    process_return = malloc(sizeof(uint8_t));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;

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

            if (node == NULL) continue;

            if (node->type != QET_NEW_PACKET) {
                //probably an error but good to check
                destroy_qnode(node);
                continue;
            }

            packet = node->data;
            packet_info = node->data + sizeof(PACKET);

            destroy_qnode(node);

            memcpy(&packet_header, packet, sizeof(packet_header));

            //todo handle all types of packets
            switch (packet_header.pac_type) {
                case MSG_INIT_PACKET:
                    mac_address_len = 6;
                    mac_address = calloc(1, mac_address_len);
                    if (mac_address == NULL) {
                        fprintf(stderr, "malloc() failed in device_discovery_receiving\n");
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        return process_return;
                    }

                    if (SendARP(packet_info->address.sin_addr.S_un.S_addr,INADDR_ANY, mac_address, p_mac_address_len)
                        != NO_ERROR) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free(mac_address);
                        return process_return;
                        }

                    memcpy(packet_info->mac_address, mac_address, mac_address_len);
                    packet_info->mac_address_len = mac_address_len;

                    free(mac_address);

                    pthread_mutex_lock(&(args->devices->mutex));

                    found_dev = device_exists(args->devices, packet_info);
                    if (found_dev != NULL) {
                        found_dev->packet.timestamp = time(NULL); //renew the timestamp
                        pthread_mutex_unlock(&args->devices->mutex);
                        continue;
                    }

                    temp_dev = malloc(sizeof(PACKET_NODE));
                    if (temp_dev == NULL) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        return process_return;
                    }
                    memcpy(&(temp_dev->packet), &packet_info, sizeof(PACKET_INFO));

                    temp_dev->next = args->devices->head;
                    args->devices->head = temp_dev;

                    pthread_mutex_unlock(&(args->devices->mutex));

                    //send signing request
                    randombytes_buf(nonce,INDIGO_NONCE_SIZE);
                    build_packet(packet,MSG_SIGNING_REQUEST,nonce);
                    send_packet((int)htonl(PORT),temp_dev->packet.address.sin_addr.S_un.S_addr,
                        temp_dev->packet.socket,packet, args->flag);
                    //todo: add a singing expected packet to the list

                    break;
                case MSG_SIGNING_REQUEST:
                    //sign the nonce and send the signature with the public key and a new nonce
                    if (sign_buffer(args->signing_keys, packet->data, INDIGO_NONCE_SIZE,signed_nonce,NULL)) {
                        //IDK do something
                        continue;
                    }
                    build_packet(packet, MSG_SIGNING_RESPONSE, NULL);

                    memcpy(packet->data, signed_nonce, sizeof(signed_nonce));

                    sodium_mprotect_readonly(args->signing_keys);
                    memcpy(packet->data + sizeof(signed_nonce), args->signing_keys->public
                        , sizeof(args->signing_keys->public));
                    sodium_mprotect_noaccess(args->signing_keys);

                    randombytes_buf(nonce,INDIGO_NONCE_SIZE);
                    memcpy(packet->data + sizeof(signed_nonce) + crypto_sign_PUBLICKEYBYTES,nonce
                        , INDIGO_NONCE_SIZE);
                //todo set the an expected packet, keep the nonce we sent
                //todo: make sure all override flags are risen in the thread_manager
                    send_packet((int)htonl(PORT),packet_info->address.sin_addr.S_un.S_addr,packet_info->socket
                        ,packet,args->flag);
                    break;
                case MSG_SIGNING_RESPONSE:
                    //todo: verify the signature and store the public key to the device node

                    ret = crypto_sign_open(nonce,NULL, packet->data, INDIGO_NONCE_SIZE + crypto_sign_BYTES
                    ,(unsigned char *)(packet->data + sizeof(signed_nonce) + crypto_sign_PUBLICKEYBYTES));
                    if (ret) {
                        //todo: mark this device to be blocked, or just ghost, or send error message
                    }

                    //todo check the nonce with the nonce we sent to be signed and then proceed
                    //todo better send error message, track the failed attempts and then ban

                    //todo if we haven't verified this device send a signing request
                case MSG_RESEND:
                case MSG_FILE_CHUNK:
                case MSG_STOP_FILE_TRANSMISSION:
                case MSG_PAUSE_FILE_TRANSMISSION:
                case MSG_CONTINUE_FILE_TRANSMISSION:
                case MSG_ERR:
                default:
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
                if (!queue_is_empty(args->queue)) continue;
            }
            else iterations_until_cleanup = 10;

            /////////////////////////////////////////
            ///  phase 2: update the device list  ///
            /////////////////////////////////////////

            curr_time = time(NULL);

            pthread_mutex_lock(&(args->devices->mutex));
            lowest_time = curr_time - args->devices->head->packet.timestamp;
            for (PACKET_NODE *temp = args->devices->head; temp != NULL; temp = temp->next) {
                time_diff = curr_time - temp->packet.timestamp;
                if (time_diff > DEVICE_TIME_UNTIL_DISCONNECTED)
                    remove_device(args->devices,&(temp->packet));
                if (time_diff < lowest_time) lowest_time = time_diff;
            }
            pthread_mutex_unlock(&(args->devices->mutex));

            //there is no need to sleep if there is more stuff to do
            if (!queue_is_empty(args->queue)) continue;

            /////////////////////////////////////////////
            ///  phase 3: wait a little and go again  ///
            /////////////////////////////////////////////
            clock_gettime(CLOCK_REALTIME,&ts);
            ts.tv_sec +=lowest_time;

            pthread_mutex_lock(&args->flag->mutex);
            pthread_cond_timedwait(&args->flag->cond,&args->flag->mutex,&ts);
            pthread_mutex_unlock(&args->flag->mutex);

        }
    }
        return process_return;
}