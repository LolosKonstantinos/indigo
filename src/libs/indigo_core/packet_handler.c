//
// Created by Constantin on 26/01/2026.
//

#include <indigo_core/packet_handler.h>
#include <indigo_errors.h>
#include <Queue.h>
#include <math.h>
#include <sodium/crypto_kx.h>
#include "indigo_types.h"

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

//todo: search in the tree works by providing a struct of the data with the fields that act as a key initialized
//todo: check if the file sending and receiving works, see it like the final check you would anyway do
//todo: check if session creation is ok
//todo: implement control signals and ip change
//todo: i know for sure that there is some code around here that does not work at all, we need to find it
//todo: we use 2 magic numbers, one for encrypted and one for unencrypted packets, distinguish them, and handle them
//todo: decrypt packets before checking the packet type
int *packet_handler_thread(PACKET_HANDLER_ARGS *args) {
    uint32_t flag_val = 0;
    QNODE *node = NULL;

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
    udp_packet_header_t packet_header;
    remote_device_t rdev;
    remote_device_t *found_rdev = NULL;

    signing_request_data_t *signing_request_data = NULL;
    signing_response_data_t *signing_response_data = NULL;
    file_sending_request_data_t *file_sending_request_data = NULL;
    file_sending_response_data_t *file_sending_response_data = NULL;

    //the expected signing response table
    tree_t *xsr_tree = NULL;
    xsr_t xsr;
    xsr_t *found_xsr = NULL;

    //the expected file packet table
    tree_t *xfp_tree = NULL;
    xfp_t xfp;
    xfp_t *found_xfp = NULL;

    Q_FILE_SENDING_REQUEST *fwd = NULL;

    session_t *session = NULL;
    session_t *found_session = NULL;
    unsigned char *session_pk = NULL;
    unsigned char *session_sk = NULL;

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

    signing_request_data = malloc(sizeof(signing_request_data_t));
    signing_response_data = malloc(sizeof(signing_response_data_t));
    file_sending_request_data = malloc(sizeof(file_sending_request_data_t));
    file_sending_response_data = malloc(sizeof(file_sending_response_data_t));
    if (!signing_request_data || !signing_response_data || !file_sending_request_data || !file_sending_response_data) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //the less the private key is exposed the better, we copy the public key since it is frequently used
    memcpy(public_key, args->signing_keys->public, crypto_sign_PUBLICKEYBYTES);

    //create the expected packet table
    ret = new_tree(&xsr_tree, cmp_xsr, sizeof(xsr_t), BINARY_TREE_TYPE_AVL);
    if (!ret) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    ret = new_tree(&xfp_tree, cmp_xfp, sizeof(xfp_t), BINARY_TREE_TYPE_AVL);
    if (!ret) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    //the main loop
    while (!termination_is_on(args->flag)) {
        ///////////////////////////////////
        ///  phase 1: check for events  ///
        ///////////////////////////////////

        flag_val = get_event_flag(args->flag);
        if (flag_val & EF_TERMINATION) break;

        if (flag_val & EF_NEW_PACKET) {
            reset_single_event(args->flag, EF_NEW_PACKET);

            node = queue_pop(args->queue,QOPT_NON_BLOCK);

            if (node == NULL) continue;

            if (node->type == QET_NEW_PACKET) {
                //extract the contents of the node
                packet = node->data;
                packet_info = node->data + sizeof(packet_t);

                destroy_qnode(node);
                node = NULL;

                //prepare the remote device struct to fill with the remote device info
                //we zero so that previous garbage doesn't affect the new device
                memset(&rdev, 0, sizeof(remote_device_t));
                //most of the time we need to search the tree so we just copy it from the start
                memcpy(rdev.peer_pk, packet->id, crypto_sign_PUBLICKEYBYTES);

                //check if the packet is encrypted
                if (packet->magic_number == MAGIC_NUMBER_2) {
                    ret = args->device_tree->search(args->device_tree, &rdev);
                    if (ret) {
                        //we cant decrypt a packet from a device we don't know

                        //we no longer need the packet
                        args->mempool->free(args->mempool,packet);
                        packet = NULL;
                        packet_info = NULL;
                        continue;
                    }
                    /* the most likely is that we need to use the server receive key.
                     * we first try to decrypt with the server key. If it fails,
                     * we try to decrypt with the client key.
                     * If it fails then, something went wrong, it is either an attacker
                     * or a weird error on the other side
                     * It should be fast enough, it fails on the tag recalculation not the decryption
                     */
                    //todo: change the system so that we need to perform only one decryption
                    /*todo: one idea is to have separate keys for each session and the peers public key
                     * is the identifier in both the session tree and the packet id field
                     */
                    ret = decrypt_packet(packet, rdev.server_rk);
                    if (ret) {
                        ret = decrypt_packet(packet, rdev.client_rk);
                        if (ret) {
                            //we no longer need the packet
                            args->mempool->free(args->mempool,packet);
                            packet = NULL;
                            packet_info = NULL;

                            continue;
                        }
                    }
                }

                memcpy(&packet_header, packet, sizeof(packet_header));


                //todo handle all types of packets
                switch (packet_header.pac_type) {
                case MSG_INIT_PACKET:
                    //validate the public key (this is not decryption, nothing is encrypted here)
                    ret = crypto_sign_verify_detached(((init_packet_data_t *)packet->data)->signature
                                            ,(unsigned char *)packet
                                            , offsetof(packet_t, data) + offsetof(init_packet_data_t, signature)
                                            , packet->id);

                    if (!ret){
                        //validate timestamp
                        //todo: this is not valid for unsynchronised offline systems
                        curr_time = time(NULL);
                        if ((((init_packet_data_t *)packet)->timestamp < curr_time - 1)
                            || (((init_packet_data_t *)packet)->timestamp > curr_time)) {

                            printf("DEBUG: time rejected");
                            fflush(stdout);
                            break;
                            }
                    }
                    else break;

                    //search in the tree
                    ret = args->device_tree->search_pin(args->device_tree, &rdev, (void **)&found_rdev);

                    if (ret == 0) {
                        found_rdev->expiration_time = time(NULL); //renew the timestamp
                        found_rdev->ip = packet_info->address.sin_addr.S_un.S_addr;

                        //copy the username
                        sanitize_username(((init_packet_data_t *)packet)->username);
                        memcpy(found_rdev->username, ((init_packet_data_t *)packet)->username, MAX_USERNAME_LEN);

                        args->device_tree->search_release(args->device_tree);
                        break;
                    }
                    args->device_tree->search_release(args->device_tree);

                    //the remote device is not on the tree so we add it
                    rdev.expiration_time = time(NULL);
                    rdev.ip = packet_info->address.sin_addr.S_un.S_addr;
                    rdev.client_rk = NULL;
                    rdev.client_tk = NULL;
                    rdev.server_rk = NULL;
                    rdev.server_tk = NULL;
                    rdev.dev_state_flag = RDSF_UNVERIFIED; //the device is not verified

                    ret = args->device_tree->insert(args->device_tree, &rdev);

                    if (ret) {
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        goto cleanup;
                    }

                    //send signing request
                    randombytes_buf(signing_request_data->nonce,INDIGO_NONCE_SIZE);
                    signing_request_data->timestamp = time(NULL);

                    build_packet(packet, MSG_SIGNING_REQUEST,public_key,NULL, signing_request_data);

                    ret = crypto_sign_detached(signing_request_data->signature
                                      ,NULL
                                      ,(unsigned char *)packet
                                      ,offsetof(packet_t, data) + offsetof(signing_request_data_t, signature)
                                      ,args->signing_keys->secret);
                    if (ret) {
                        *process_return = INDIGO_ERROR_INVALID_PARAM;
                        goto cleanup;
                    }

                    ret = send_packet((int)htonl(PORT),packet_info->address.sin_addr.S_un.S_addr,
                                args->sockets,packet, args->flag);

                    if (ret) {
                        switch (ret) {
                        case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                        case INDIGO_ERROR_INVALID_PARAM:
                        case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                            *process_return = ret;
                            goto cleanup;
                        case INDIGO_ERROR_NO_SYS_RESOURCES: //todo: I don't think we should terminate for that
                            break;
                        case INDIGO_ERROR_NETWORK_RESET:
                            set_event_flag(args->flag, EF_RESET_SOCKETS);
                            break;
                        default:
                            break; //winlib errors go here
                        }
                    }

                    //add signing response to expected packets
                    xsr.expiration_time = time(NULL) + EXPIRATION_TIME;
                    memcpy(xsr.nonce, signing_request_data->nonce, INDIGO_NONCE_SIZE);

                    memset(signing_request_data,0, sizeof(signing_request_data_t));

                    if (xsr_tree->insert(xsr_tree, &xsr)) {
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        goto cleanup;
                    }

                    break;
                case MSG_SIGNING_REQUEST:
                    //validate the public key
                    ret = crypto_sign_verify_detached(((signing_request_data_t *)packet->data)->signature
                                            ,(unsigned char *)packet
                                            , offsetof(packet_t, data) + offsetof(signing_request_data_t, signature)
                                            , packet->id);
                    //todo: time errors probable (same as above)
                    if (!ret){
                        //validate the timestamp
                        curr_time = time(NULL);
                        if ((((signing_request_data_t *)packet)->timestamp < curr_time - 1)
                            || (((signing_request_data_t *)packet)->timestamp > curr_time)) {

                            printf("DEBUG: time rejected");
                            fflush(stdout);
                            break;
                            }
                    }
                    else break;

                    //sign the nonce and send the signature with the public key and a new nonce
                    ret = sign_buffer(args->signing_keys,((signing_request_data_t *)packet->data)->nonce
                        , INDIGO_NONCE_SIZE
                        ,signing_response_data->signed_nonce
                        ,NULL);
                    //can fail only dew to wrong usage
                    if (ret) {
                        *process_return = INDIGO_ERROR_INVALID_PARAM;
                        goto cleanup;
                    }

                    //create session keys
                    session_pk = malloc(crypto_kx_PUBLICKEYBYTES);
                    session_sk = malloc(crypto_kx_SECRETKEYBYTES);
                    if (!session_pk || !session_sk) {
                        free(session_pk);
                        free(session_sk);
                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                        goto cleanup;
                    }
                    sodium_mlock(session_sk,crypto_kx_SECRETKEYBYTES);

                    ret = crypto_kx_keypair(session_pk,session_sk);
                    if (ret) {
                        free(session_pk);
                        free(session_sk);
                        printf("DEBUG: kx_keypair failed");
                        fflush(stdout);
                        *process_return = INDIGO_ERROR_INVALID_PARAM;
                        goto cleanup;
                    }

                    memcpy(signing_response_data->pkx,session_pk, crypto_kx_PUBLICKEYBYTES);
                    signing_response_data->zero = 0;


                    //if the peer is verified we don't need to send a signing request
                    ret = args->device_tree->search_pin(args->device_tree, &rdev, (void **)&found_rdev);
                    if (ret == 0) {
                        //the device is found

                        found_rdev->expiration_time = time(NULL) + EXPIRATION_TIME;
                        found_rdev->ip = packet_info->address.sin_addr.S_un.S_addr;

                        if (found_rdev->dev_state_flag == RDSF_UNVERIFIED) {
                            randombytes_buf(signing_response_data->nonce,INDIGO_NONCE_SIZE);
                            signing_response_data->sig_request = 1;
                            //insert into xsr
                            xsr.expiration_time = time(NULL) + EXPIRATION_TIME;
                            xsr.pkx = session_pk;
                            xsr.skx = session_sk;
                            memcpy(xsr.nonce, signing_response_data->nonce, INDIGO_NONCE_SIZE);
                            memcpy(xsr.id, packet->id, crypto_sign_PUBLICKEYBYTES);
                            ret = xsr_tree->insert(xsr_tree, &xsr);
                            if (ret) {
                                printf("DEBUG: xsr_tree->insert() failed in packet_handler");
                                fflush(stdout);
                                args->device_tree->search_release(args->device_tree);
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                goto cleanup;
                            }
                        }
                        else {
                            //we don't need to send a signature request, we erase the nonce and turn off the flag
                            memset(signing_response_data->nonce,0,INDIGO_NONCE_SIZE);
                            signing_response_data->sig_request = 0;
                        }
                        args->device_tree->search_release(args->device_tree);
                    }
                    //in this case they found us before we received their discovery packet (if they sent any)
                    else {
                        args->device_tree->search_release(args->device_tree);
                        //add the device to the device table
                        //we detected the device (though it is unverified)
                        rdev.expiration_time = time(NULL) + EXPIRATION_TIME;
                        rdev.ip = packet_info->address.sin_addr.S_un.S_addr;
                        memcpy(rdev.peer_pk, packet->id, crypto_sign_PUBLICKEYBYTES);
                        rdev.dev_state_flag = RDSF_UNVERIFIED; //the device is not verified

                        ret = args->device_tree->insert(args->device_tree, &rdev);
                        if (ret) {
                            free(session_pk);
                            free(session_sk);
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            goto cleanup;
                        }

                        //send a nonce to verify them
                        randombytes_buf(signing_response_data->nonce,INDIGO_NONCE_SIZE);
                        signing_response_data->sig_request = 1;
                        //add signing response to expected packets
                        xsr.expiration_time = time(NULL) + EXPIRATION_TIME;
                        xsr.pkx = session_pk;
                        xsr.skx = session_sk;
                        memcpy(xsr.nonce, signing_response_data->nonce, INDIGO_NONCE_SIZE);
                        memcpy(xsr.id, packet->id, crypto_sign_PUBLICKEYBYTES);

                        if (xsr_tree->insert(xsr_tree, &xsr)) {
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            goto cleanup;
                        }
                        memset(&xsr,0,sizeof(xsr_t));
                    }
                    build_packet(packet, MSG_SIGNING_RESPONSE, public_key, NULL,signing_response_data);
                    ret = crypto_sign_detached(signing_response_data->signature
                                  ,NULL
                                  ,(unsigned char *)packet
                                  ,offsetof(packet_t, data) + offsetof(signing_request_data_t, signature)
                                  ,args->signing_keys->secret);
                    if (ret) {
                        *process_return = INDIGO_ERROR_INVALID_PARAM;
                        goto cleanup;
                    }

                    ret = send_packet((int)htonl(PORT),packet_info->address.sin_addr.S_un.S_addr
                                      ,args->sockets
                                      ,packet, args->flag);
                    if (ret) {
                        switch (ret) {
                        case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                        case INDIGO_ERROR_INVALID_PARAM:
                        case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                            *process_return = ret;
                            goto cleanup;
                        case INDIGO_ERROR_NO_SYS_RESOURCES: //todo: I don't think we should terminate for that
                            break;
                        case INDIGO_ERROR_NETWORK_RESET:
                            set_event_flag(args->flag, EF_RESET_SOCKETS);
                            break;
                        default:
                            break; //winlib errors go here
                        }
                    }
                    break;

                case MSG_SIGNING_RESPONSE:
                    ret = crypto_sign_verify_detached(((signing_response_data_t *)packet->data)->signature
                                            ,(unsigned char *)packet
                                            , offsetof(packet_t, data) + offsetof(signing_response_data_t, signature)
                                            , packet->id);
                    if (ret) break; //we don't validate signed time, since there is already a signed nonce to verify

                    memcpy(xsr.id, packet->id, crypto_sign_PUBLICKEYBYTES);
                    ret = xsr_tree->search(xsr_tree, &xsr);
                    if (ret) break; //if there is no expected signing response, there is nothing to process

                    //verify the signed nonce
                    ret = crypto_sign_open(nonce,NULL,
                            ((signing_response_data_t *)packet->data)->signed_nonce,
                            INDIGO_NONCE_SIZE + crypto_sign_BYTES,
                            packet->id);
                    if (ret == 0) {
                        //if the nonce signed is the same as the one we sent to be signed
                        if (memcmp(xsr.nonce, nonce,INDIGO_NONCE_SIZE) == 0) {
                            //the device got verified
                            //todo: so we need to create the client and server keys, if we need to sing nonce, we create keys no xsr, otherwise use xsr
                            ret = args->device_tree->search_pin(args->device_tree, &rdev, (void **)&found_rdev);
                            /* I am not sure how we could get an expected packet for a device
                             * that isn't in the device tree
                             */
                            if (ret == 0) {
                                found_rdev->expiration_time = time(NULL) + EXPIRATION_TIME;
                                found_rdev->ip = packet_info->address.sin_addr.S_un.S_addr;//ip may have changed

                                found_rdev->dev_state_flag |= RDSF_VERIFIED;

                                //check if we need to verify ourselves
                                if (((signing_response_data_t *)(packet->data))->sig_request) {
                                    signing_response_data->zero = 0;
                                    signing_response_data->sig_request = 0;
                                    memset(signing_response_data->nonce,0,INDIGO_NONCE_SIZE);

                                    ret = crypto_sign(signing_response_data->signed_nonce
                                        , NULL
                                        , ((signing_response_data_t *)packet->data)->nonce
                                        , INDIGO_NONCE_SIZE
                                        , args->signing_keys->secret);
                                    if (ret) {
                                        *process_return = INDIGO_ERROR_INVALID_PARAM;
                                        goto cleanup;
                                    }

                                    //create session keys
                                    /*there is no possible way to have a situation where,
                                     * we have created session keys but the other party hasn't verified us
                                     * it could happen if the other party runs slightly modified code, me not happy
                                     */

                                    session_pk = malloc(crypto_kx_PUBLICKEYBYTES);
                                    session_sk = malloc(crypto_kx_SECRETKEYBYTES);
                                    if (!session_pk || !session_sk) {
                                        free(session_pk);
                                        free(session_sk);
                                        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                        goto cleanup;
                                    }
                                    sodium_mlock(session_sk,crypto_kx_SECRETKEYBYTES);

                                    ret = crypto_kx_keypair(session_pk,session_sk);
                                    if (ret) {
                                        free(session_pk);
                                        free(session_sk);
                                        printf("DEBUG: kx_keypair failed");
                                        fflush(stdout);
                                        *process_return = INDIGO_ERROR_INVALID_PARAM;
                                        goto cleanup;
                                    }
                                    ret = crypto_kx_client_session_keys(found_rdev->client_rk
                                        , found_rdev->client_tk
                                        , session_pk
                                        , session_sk
                                        , ((signing_response_data_t *)packet->data)->pkx);
                                    if (ret) {
                                        //the peer's public key is not acceptable
                                        free(session_pk);
                                        free(session_sk);
                                        break;
                                    }

                                    ret = crypto_kx_server_session_keys(found_rdev->server_rk
                                        , found_rdev->server_tk
                                        , session_pk
                                        , session_sk
                                        , ((signing_response_data_t *)packet->data)->pkx);
                                    if (ret) {
                                        //the peer's public key is not acceptable
                                        free(session_pk);
                                        free(session_sk);
                                        break;
                                    }

                                    memcpy(signing_response_data->pkx,session_pk, crypto_kx_PUBLICKEYBYTES);

                                    //we no longer need the keys
                                    free(session_pk);
                                    free(session_sk);
                                    session_pk = NULL;
                                    session_sk = NULL;

                                    build_packet(packet, MSG_SIGNING_RESPONSE, public_key, NULL,signing_response_data);
                                    ret = crypto_sign_detached(signing_response_data->signature, NULL
                                        ,(unsigned char *)packet
                                        , offsetof(packet_t, data) + offsetof(signing_response_data_t, signature)
                                        ,public_key);
                                    if (ret) {
                                        *process_return = INDIGO_ERROR_INVALID_PARAM;
                                        goto cleanup;
                                    }
                                    ret = send_packet((int)htonl(PORT)
                                                      ,packet_info->address.sin_addr.S_un.S_addr
                                                      ,args->sockets
                                                      ,packet, args->flag);
                                    if (ret) {
                                        switch (ret) {
                                        case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                                        case INDIGO_ERROR_INVALID_PARAM:
                                        case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                                            *process_return = ret;
                                            goto cleanup;
                                        case INDIGO_ERROR_NO_SYS_RESOURCES: //todo: I don't think we should terminate for that
                                            break;
                                        case INDIGO_ERROR_NETWORK_RESET:
                                            set_event_flag(args->flag, EF_RESET_SOCKETS);
                                            break;
                                        default:
                                            break; //winlib errors go here
                                        }
                                    }
                                }
                                else {
                                    //todo: improve error handling
                                    //create the client and server keys
                                    ret = crypto_kx_client_session_keys(found_rdev->client_rk
                                        , found_rdev->client_tk
                                        , xsr.pkx
                                        , xsr.skx
                                        , ((signing_response_data_t *)packet->data)->pkx);
                                    if (ret) {
                                        //the peer's public key is not acceptable
                                        break;
                                    }

                                    ret = crypto_kx_server_session_keys(found_rdev->server_rk
                                        , found_rdev->server_tk
                                        , xsr.pkx
                                        , xsr.skx
                                        , ((signing_response_data_t *)packet->data)->pkx);
                                    if (ret) {
                                        //the peer's public key is not acceptable
                                        break;
                                    }
                                }
                            }

                            args->device_tree->search_release(args->device_tree);

                            //remove the expected packet
                            free(xsr.pkx);
                            free(xsr.skx);
                            xsr_tree->remove(xsr_tree, &xsr);
                        }
                    }
                    break;
                case MSG_FILE_SENDING_REQUEST:{
                        //we need permission to proceed, so we push it to the manager to handle
                        //tell the interface (cli or gui via queue), the interface will ask the user
                        //if the user agrees, we send back a response containing the preferred session serial number
                        //if it gets accepted we receive a session_t struct via queue, and store an expected file packet

                        Q_FILE_SENDING_REQUEST *fsr = malloc(sizeof(Q_FILE_SENDING_REQUEST));
                        if (!fsr) {
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            goto cleanup;
                        }
                        memcpy(fsr->id, packet->id, crypto_sign_PUBLICKEYBYTES);
                        memcpy(&(fsr->file_size), packet->data + crypto_kx_PUBLICKEYBYTES, sizeof(size_t));
                        wcsncpy(fsr->file_name
                               ,(wchar_t *)(packet->data + crypto_kx_PUBLICKEYBYTES + sizeof(size_t))
                               ,MAX_PATH);
                        fsr->file_name[MAX_PATH - 1] = L'\0';
                        fsr->addr = packet_info->address.sin_addr.S_un.S_addr;

                        if (queue_push(args->cli_queue, fsr, QET_FILE_SENDING_REQUEST)) {
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            goto cleanup;
                        }
                        break;
                }
                case MSG_FILE_SENDING_RESPONSE:
                    ret = create_client_session(packet
                                                , packet_info
                                                , args->device_tree
                                                , args->session_tree
                                                , xfp_tree
                                                , args->send_queue
                    );
                    if (ret) {
                        *process_return = ret;
                        goto cleanup;
                    }
                    break;
                case MSG_FILE_CHUNK:{
                        /*TODO: the thing is that the file descriptor is in xfp, (and we need to check xfp anyway
                         *      but we need to update the session too, it contains stats mainly
                         *      we will do only one tree search, idc, and xfp needs to be found
                         *      we may have to merge xfp and session
                         *      session is not used as for now, i think its for the ui primarily
                         *      FOR NOW JUST DO 2 SEARCHES AND UPDATE BOTH
                         */
                        size_t ret_val;
                        uint64_t chunk_number;
                        packet_t temp_packet;

                        memcpy(xfp.session_id.pk, packet->id, crypto_sign_PUBLICKEYBYTES);
                        xfp.session_id.serial = ((file_chunk_data_t *)packet->data)->serial;
                        ret = xfp_tree->search_pin(xfp_tree, &xfp, (void **)&found_xfp);
                        if (ret) {
                            xfp_tree->search_release(xfp_tree);
                            break;
                        }

                        memcpy(&(session->session_id), &(xfp.session_id), sizeof(session_id_t));
                        ret = args->session_tree->search_pin(args->session_tree, session, (void **)&found_session);
                        if (ret) {
                            xfp_tree->search_release(xfp_tree);
                            args->session_tree->search_release(args->session_tree);
                            break;
                        }

                        found_xfp->expiration_time = EXPIRATION_TIME;
                        chunk_number = ((file_chunk_data_t *)packet->data)->chunk_number;
                        if (chunk_number < found_xfp->packet_number) {
                            //we either received a duplicate packet or a resend
                            //todo: we dont want to write duplicate packets, but it may also be a re-sent packet
                            //in this case we dont update the packet number
                        }
                        if (chunk_number > found_xfp->packet_number) {
                            //we lost a packet, send a re-send packet

                            //create the packet
                            build_packet(&temp_packet, MSG_RESEND, public_key, NULL, NULL);
                            ((transmission_control_data_t *)(temp_packet.data))->serial = ((file_chunk_data_t *)packet->data)->serial;
                            ((transmission_control_data_t *)(temp_packet.data))->first_packet_number = found_xfp->packet_number;
                            ((transmission_control_data_t *)(temp_packet.data))->last_packet_number = chunk_number - 1;
                            //send the packet
                            ret = send_packet(htons(PORT)
                                ,packet_info->address.sin_addr.S_un.S_addr
                                , args->sockets
                                , &temp_packet
                                , args->flag);
                            if (ret) {
                                switch (ret) {
                                case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                                case INDIGO_ERROR_INVALID_PARAM:
                                case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                                    *process_return = ret;
                                    goto cleanup;
                                case INDIGO_ERROR_NO_SYS_RESOURCES: //todo: I don't think we should terminate for that
                                    break;
                                case INDIGO_ERROR_NETWORK_RESET:
                                    set_event_flag(args->flag, EF_RESET_SOCKETS);
                                    break;
                                default:
                                    break; //winlib errors go here
                                }
                            }
                        }

                        //set the position in the file (we are not writing necessarily at the end of the last write)
                        if (chunk_number * PAC_DATA_PAYLOAD_BYTES < LLONG_MAX){
                            fseeko64(found_xfp->file
                            , (long long)(chunk_number * PAC_DATA_PAYLOAD_BYTES)
                            ,SEEK_SET);
                        }
                        else {
                            //not very sure who owns a file bigger than 2 exbi-bytes, but why not
                            fseeko64(found_xfp->file, LLONG_MAX, SEEK_SET);
                            fseeko64(found_xfp->file
                            , (long long)((chunk_number * PAC_DATA_PAYLOAD_BYTES) - LLONG_MAX)
                            , SEEK_SET);
                        }

                        ret_val = fwrite(((file_chunk_data_t *)packet->data)->data,1, PAC_DATA_PAYLOAD_BYTES, found_xfp->file);
                        if (ret_val != PAC_DATA_PAYLOAD_BYTES) {
                            ret = ferror(found_xfp->file);
                            fprintf(stderr, "DEBUG: file error in fwrite in packet_handler");
                            //todo: here are all the errors of fwrite, handle them. these are bad errors, most of them
                            switch (ret) {
                                case EAGAIN:
                                case EBADF:
                                case EFBIG:
                                case EINTR:
                                case EIO:
                                case ENOSPC:
                                case EPIPE:
                                case ENOMEM:
                                case ENXIO:
                                default:
                                    break;
                            }
                        }
                        if (chunk_number >= found_xfp->packet_number) found_xfp->packet_number = chunk_number + 1;
                        found_session->bytes_moved += PAC_DATA_PAYLOAD_BYTES;

                        xfp_tree->search_release(xfp_tree);
                        args->session_tree->search_release(args->session_tree);
                        break;
                }
                case MSG_RESEND:
                    fprintf(stderr, "DEBUG: Resend");
                    break;
                case MSG_STOP_FILE_TRANSMISSION:
                case MSG_PAUSE_FILE_TRANSMISSION:
                case MSG_CONTINUE_FILE_TRANSMISSION:
                case MSG_IP_CHANGE:
                    fprintf(stderr, "DEBUG: not implemented");
                    break;
                case MSG_ERR:
                    fprintf(stderr, "DEBUG: RECEIVED ERROR MSG");
                    break;
                default:
                    printf("\noops...\n");
                    break;
                }

                //we no longer need the packet
                args->mempool->free(args->mempool,packet);
                packet = NULL;
                packet_info = NULL;
            }
            else if (node->type == QET_SESSION_START) {
                //they sent us a send request and the user said yes
                fwd = node->data;
                ret = create_server_session(fwd,args->device_tree, args->session_tree,xfp_tree,public_key, args->sockets, args->flag);
                free(fwd);
                if (ret) {
                    //todo: create_server_session() uses send_packet() and returns its errors
                    //todo: do more complex error handling
                    *process_return = ret;
                    goto cleanup;
                }
                destroy_qnode(node);
                node = NULL;
            }
            else if (node->type == QET_EXPECT_SEND_RESPONSE) {
                //we sent a request to send a file, and we expect a response to that request
                memset(&xfp, 0 , sizeof(xfp_t));
                memcpy(&(xfp.session_id), node->data, sizeof(session_id_t));
                free(node->data);
                destroy_qnode(node);
                node = NULL;

                ret = xfp_tree->insert(xfp_tree, &xfp);
                if (ret) {
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    goto cleanup;
                }
            }
            else {
                //probably an error but good to check
                destroy_qnode(node);
                node = NULL;
                continue;
            }
        }

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
    free_tree(xsr_tree);
    free_tree(xfp_tree);
    free(signing_request_data);
    free(signing_response_data);
    free(file_sending_request_data);
    free(file_sending_response_data);
    return process_return;

    cleanup:
    destroy_qnode(node);
    free_tree(xsr_tree);
    free_tree(xfp_tree);
    free(signing_request_data);
    free(signing_response_data);
    free(file_sending_request_data);
    free(file_sending_response_data);

    set_event_flag(args->flag, EF_TERMINATION);
    set_event_flag(args->wake, EF_WAKE_MANAGER);
    return process_return;
}

//cmp functions (helpers)
int cmp_xsr(void *s1, void *s2) {
    return memcmp(((xsr_t *)s1)->id, ((xsr_t *)s2)->id, crypto_kx_PUBLICKEYBYTES);
}

int cmp_xfp(void *s1, void *s2) {
    return memcmp(&((xfp_t *)s1)->session_id, &((xfp_t *)s2)->session_id, (sizeof(uint64_t) + crypto_sign_PUBLICKEYBYTES));
}


int create_server_session(Q_FILE_SENDING_REQUEST *fwd
                          , tree_t *dev_tree
                          , tree_t *session_tree
                          , tree_t *xfp_tree
                          , unsigned char pk[crypto_sign_PUBLICKEYBYTES]
                          , socket_ll* sockets
                          , EFLAG *flag) {
    //they sent us a send request and the user said yes

    int ret;
    remote_device_t rdev;
    packet_t *packet = NULL;
    session_t *session = NULL;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    file_sending_response_data_t file_sending_response_data = {0};
    xfp_t xfp;

    memcpy(&(rdev.peer_pk),fwd->id,crypto_sign_PUBLICKEYBYTES);
    ret = dev_tree->search(dev_tree, &rdev);
    if (ret) {
        //we didnt find them
        ret = 1;
        goto cleanup;
    }

    //necessary allocations
    packet = malloc(sizeof(struct udp_packet_t));
    session = malloc(sizeof(session_t));
    if (!session || !packet) {
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    xfp.file = tmpfile();
    if (!xfp.file) {
        ret = INDIGO_ERROR_CAN_NOT_OPEN_FILE;
        goto cleanup;
    }

    //todo: check if the serial is in the currently used fids
    if (rdev.last_fid >= fwd->serial) {
        ret = INDIGO_ERROR_INVALID_PEER_PARAM;
        goto cleanup;
    }
    file_sending_response_data.serial = fwd->serial;

    //todo: why do we sent a nonce?
    randombytes_buf(nonce,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    build_packet(packet, MSG_FILE_SENDING_RESPONSE,pk,nonce, &file_sending_response_data);
    ret = encrypt_packet(packet, rdev.server_tk, nonce);
    if (ret) {
        goto cleanup;
    }

    ret = send_packet(htons(PORT),fwd->addr,sockets,packet, flag);
    if (ret) goto cleanup; //it's up to the caller to handle these errors, we cant do anything

    free(packet);
    packet = NULL;
    //create expected file packets
    xfp.expiration_time = time(NULL) + EXPIRATION_TIME;
    xfp.packet_number = (uint64_t)ceil((double)(fwd->file_size)/(double)10);
    xfp.session_id.serial = 0; //todo: assign the smallest valid serial number
    memcpy(xfp.session_id.pk,fwd->id,crypto_sign_PUBLICKEYBYTES);

    ret = xfp_tree->insert(xfp_tree,&xfp);
    if (ret) goto cleanup;

    memcpy(&(session->session_id), &(xfp.session_id), sizeof(session_id_t));
    session->bytes_moved = 0;
    session->start_time = time(NULL);
    session->status_flags = 0;
    session->port = htons(PORT);
    session->ip = fwd->addr;

    ret = session_tree->insert(session_tree,session);
    if (ret) goto cleanup;

    return 0;

    cleanup:
    free(packet);
    free(session);
    return ret;
}

int create_client_session(const packet_t *const packet
                          , const packet_info_t *const packet_info
                          , tree_t *dev_tree
                          , tree_t *session_tree
                          , tree_t *xfp_tree
                          , QUEUE *send_queue) {
    //we got their one time public key, and confirmation to proceed
    //we calculate the send key
    //tell the sending thread to start sending the file
    int ret;
    remote_device_t rdev;
    session_t *session = NULL;
    active_file_t *tmp_active_file = NULL;
    xfp_t xfp;

    //check if the peer is in the device tree (if they are not, we shouldn't create a session)
    ret = dev_tree->search(dev_tree, &rdev);
    if (ret) goto cleanup;

    //add an expected file packet (xfp) for this session
    memcpy(&(xfp.session_id.pk), packet->id, crypto_sign_PUBLICKEYBYTES);
    xfp.session_id.serial = ((file_sending_response_data_t *)(packet->data))->serial;
    ret = xfp_tree->search(xfp_tree, &xfp);
    if (ret) goto cleanup;

    //necessary allocations
    tmp_active_file = malloc(sizeof(active_file_t));
    session = malloc(sizeof(session_t));
    if (!session || !tmp_active_file) {
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    memcpy(&(session->session_id), &(xfp.session_id), sizeof(session_id_t));
    session->bytes_moved = 0;
    session->start_time = time(NULL);
    session->status_flags = 0;
    session->port = htons(PORT);
    session->ip = packet_info->address.sin_addr.S_un.S_addr;


    ret = session_tree->insert(session_tree,session);
    if (ret) goto cleanup;

    tmp_active_file->fd = xfp.file; //todo xfp should contain a file descriptor, as for now it is not initialized
    tmp_active_file->counter = 0;
    tmp_active_file->next = NULL;

    ret = queue_push(send_queue, tmp_active_file,QET_SEND_FILE);
    if (ret != 0) goto cleanup;

    xfp_tree->remove(xfp_tree,&xfp);
    return 0;

    cleanup:
    free(tmp_active_file);
    free(session);
    xfp_tree->remove(xfp_tree,&xfp);
    return ret;
}

int sanitize_username(wchar_t username[MAX_USERNAME_LEN]) {
    if (username == NULL) return 1;

    username[MAX_USERNAME_LEN - 1] = L'\0';
    for (int i = 0; i < MAX_USERNAME_LEN; i++) {
        if (username[i] == '\0') break;
        if (!iswprint(username[i])) {
            memmove(username + i, username + i + 1, MAX_USERNAME_LEN - i - 1);
        }
        //may add more rules, but for now it's ok
    }
    return 0;
}