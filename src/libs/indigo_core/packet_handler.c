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

#include "binary_tree.h"
#include "event_flags.h"
#include "indigo_types.h"
#include "net_io.h"
#include <config.h>
#include <Queue.h>
#include <glib.h>
#include <indigo_core/packet_handler.h>
#include <indigo_errors.h>
#include <limits.h>
#include <math.h>
#include <sodium/crypto_kx.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <log.h>

#ifndef _WIN32
#define _FILE_OFFSET_BITS_64
#define fseeko64 fseeko
#include <errno.h>
#endif

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////

// todo: search in the tree works by providing a struct of the data with the fields that act as a key initialized
// todo: check if the file sending and receiving works, see it like the final check you would anyway do
// todo: check if session creation is ok
// todo: implement control signals and ip change
// todo: i know for sure that there is some code around here that does not work at all, we need to find it
int *packet_handler_thread(PACKET_HANDLER_ARGS *args)
{

    void *tmp_ptr;
    uint32_t flag_val = 0;
    QNODE *node = NULL;

    time_t curr_time = 0;
    struct timespec timespec;
    time_t lowest_time = 600;
    time_t time_diff = 0;

    unsigned char iterations_until_cleanup = 10;

    unsigned char nonce[INDIGO_NONCE_SIZE];

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];

    packet_t *packet = NULL;
    packet_info_t *packet_info = NULL;
    udp_packet_header_t packet_header;
    remote_device_t rdev;
    remote_device_t *found_rdev = NULL;

    signing_request_data_t *signing_request_data = NULL;
    signing_response_data_t *signing_response_data = NULL;
    file_sending_request_data_t *file_sending_request_data = NULL;
    file_sending_response_data_t *file_sending_response_data = NULL;

    // the expected signing response table
    tree_t *xsr_tree = NULL;
    xsr_t xsr;
    xsr_t *found_xsr;
    tree_iterator_t *xsr_iterator = NULL;

    // the expected file packet table
    tree_t *xfp_tree = NULL;
    xfp_t xfp = {0};
    xfp_t *found_xfp = NULL;
    tree_iterator_t *xfp_iterator = NULL;

    Q_FILE_SENDING_REQUEST *fwd = NULL;

    session_t *session = NULL;
    session_t *found_session = NULL;
    unsigned char *session_pk = NULL;
    unsigned char *session_sk = NULL;

    tree_iterator_t *session_iterator = NULL;
    tree_iterator_t *rdev_iterator = NULL;

    known_key_t known_key;
    tree_t *known_keys_tree = NULL;

    char tmp_username[MAX_USERNAME_LEN * sizeof(utf8_char_t)];

    range_node_t *range_node;
    range_node_t *prev_node;

    int ret = 0; // general purpose return variable

    int *process_return = NULL;

    // allocate memory for the return value
    if (errno) {
        // this is here because clangd is crying again
        // says I must remove errno.h
    }
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        log_fatal("[packet_handler_thread] malloc failed allocating %d bytes for return value | return NULL",
            sizeof(int));
        return NULL;
    }
    *process_return = 0;

    ret = new_tree(&known_keys_tree, key_cmp, sizeof(known_key_t), BINARY_TREE_FLAG_AVL);
    if (ret) {
        *process_return = ret;
        log_fatal("[packet_handler_thread] new_tree() failed creating known key tree | return %d", ret);
        goto cleanup;
    }
    ret = load_known_keys(known_keys_tree);
    if (ret != INDIGO_SUCCESS && ret != INDIGO_ERROR_FILE_NOT_FOUND) {
        *process_return = ret;
        log_fatal("[packet_handler_thread] load_known_keys() failed | return %d", ret);
        goto cleanup;
    }

    signing_request_data = malloc(sizeof(signing_request_data_t));
    signing_response_data = malloc(sizeof(signing_response_data_t));
    file_sending_request_data = malloc(sizeof(file_sending_request_data_t));
    file_sending_response_data = malloc(sizeof(file_sending_response_data_t));
    if (!signing_request_data || !signing_response_data || !file_sending_request_data || !file_sending_response_data) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_fatal("[packet_handler_thread] malloc failed allocating %d %d %d %d bytes for signing request"
                  " and response and file sending request and response data respectively | return %d",
                  sizeof(signing_request_data_t), sizeof(signing_response_data_t),
                  sizeof(file_sending_request_data_t), sizeof(file_sending_response_data_t) , *process_return);
        goto cleanup;
    }

    // the less the private key is exposed the better, we copy the public key since it is frequently used
    memcpy(public_key, args->signing_keys->public, crypto_sign_PUBLICKEYBYTES);

    // create the expected packet table
    ret = new_tree(&xsr_tree, cmp_xsr, sizeof(xsr_t), BINARY_TREE_FLAG_AVL);
    if (ret != INDIGO_SUCCESS) {
        *process_return = ret;
        log_fatal("[packet_handler_thread] new_tree failed to create expected signing response tree | return %d", *process_return,
            process_return);
        goto cleanup;
    }
    ret = new_tree(&xfp_tree, cmp_xfp, sizeof(xfp_t), BINARY_TREE_FLAG_AVL);
    if (ret != INDIGO_SUCCESS) {
        *process_return = ret;
        log_fatal("[packet_handler_thread] new_tree failed to create expected file packet tree | return %d",
            process_return);
        goto cleanup;
    }

    // the main loop
    while (!termination_is_on(args->flag)) {
        ///////////////////////////////////
        ///  phase 1: check for events  ///
        ///////////////////////////////////

        flag_val = get_event_flag(args->flag);
        if (flag_val & EF_TERMINATION)
            break;

        if (flag_val & EF_NEW_PACKET) {
            reset_single_event(args->flag, EF_NEW_PACKET);

            node = queue_pop(args->queue, QOPT_NON_BLOCK);

            if (node == NULL)
                continue;

            if (node->type == QET_NEW_PACKET) {
                // extract the contents of the node
                packet = node->data;
                packet_info = node->data + sizeof(packet_t);

                destroy_qnode(node);
                node = NULL;

                // prepare the remote device struct to fill with the remote device info
                // we zero so that previous garbage doesn't affect the new device
                memset(&rdev, 0, sizeof(remote_device_t));
                // most of the time we need to search the tree so we just copy it from the start
                memcpy(rdev.peer_pk, packet->id, crypto_sign_PUBLICKEYBYTES);

                // check if the packet is encrypted
                if (packet->magic_number == MAGIC_NUMBER_2) {
                    ret = args->device_tree->search(args->device_tree, &rdev);
                    if (ret == 0) {
                        // we cant decrypt a packet from a device we don't know

                        // we no longer need the packet
                        mempool_free(args->mempool, packet);
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
                    // todo: change the system so that we need to perform only one decryption

                    /*
                     * todo: one idea is to have separate keys for each session and the peers public key
                     * is the identifier in both the session tree and the packet id field
                     */
                    ret = decrypt_packet(packet, rdev.server_rk);
                    if (ret) {
                        ret = decrypt_packet(packet, rdev.client_rk);
                        if (ret) {
                            // we no longer need the packet
                            mempool_free(args->mempool, packet);
                            packet = NULL;
                            packet_info = NULL;

                            continue;
                        }
                    }
                }

                memcpy(&packet_header, packet, sizeof(packet_header));

                // todo handle all types of packets
                switch (packet_header.pac_type) {
                    case MSG_INIT_PACKET:
                        log_info("[packet_handler_thread] received init packet");
                        // validate the public key (this is not decryption, nothing is encrypted here)
                        ret = crypto_sign_verify_detached(
                            ((init_packet_data_t *)packet->data)->signature, (unsigned char *)packet,
                            offsetof(packet_t, data) + offsetof(init_packet_data_t, signature), packet->id);

                        if (ret == 0) {
                            // validate timestamp
                            // todo: this is not valid for unsynchronised offline systems
                            curr_time = time(NULL);
                            if ((((init_packet_data_t *)packet->data)->timestamp < curr_time - 60) ||
                                (((init_packet_data_t *)packet->data)->timestamp > curr_time + 60)) {
                                log_debug("[packet_handler_thread] time rejected init packet current time %lld received"
                                          " time %lld", curr_time, ((init_packet_data_t *)packet->data)->timestamp);
                                break;
                            }
                        }
                        else {
                            log_debug("[packet_handler_thread] failed to verify signed init packet ret %d",ret);
                            break;
                        }

                        // search in the tree
                        ret = args->device_tree->search_pin(args->device_tree, &rdev, (void **)&found_rdev);

                        if (ret == 1) {
                            log_debug("[packet_handler_thread] device already registered");
                            found_rdev->expiration_time = time(NULL); // renew the timestamp
                            found_rdev->ip = packet_info->address.sin_addr.s_addr;
                            // copy the username
                            memcpy(tmp_username, ((init_packet_data_t *)packet)->username,
                                   MAX_USERNAME_LEN * sizeof(wchar_t));
                            sanitize_username(tmp_username);
                            memcpy(found_rdev->username, ((init_packet_data_t *)packet)->username, MAX_USERNAME_LEN);

                            args->device_tree->search_release(args->device_tree);
                            break;
                        }
                        args->device_tree->search_release(args->device_tree);

                        // the remote device is not on the tree so we add it
                        rdev.expiration_time = time(NULL);
                        rdev.ip = packet_info->address.sin_addr.s_addr;
                        rdev.client_rk = NULL;
                        rdev.client_tk = NULL;
                        rdev.server_rk = NULL;
                        rdev.server_tk = NULL;
                        rdev.fsr_list = NULL;
                        rdev.fsr_count = 0;
                        rdev.dev_state_flag = RDSF_UNVERIFIED; // the device is not verified

                        memcpy(known_key.key, rdev.peer_pk, crypto_sign_PUBLICKEYBYTES);
                        if (known_keys_tree->search(known_keys_tree, &known_key)) {
                            rdev.dev_state_flag |= known_key.status;
                        }
                        else {
                            rdev.dev_state_flag |= KNOWN_KEY_STATUS_UNKNOWN;
                        }

                        ret = args->device_tree->insert(args->device_tree, &rdev);

                        if (ret) {
                            *process_return = ret;
                            log_fatal("[packet_handler_thread] device_tree insert() failed| return %d", ret);
                            goto cleanup;
                        }
                        log_debug("[packet_handler_thread] device inserted to tree");

                        // send signing request
                        randombytes_buf(signing_request_data->nonce, INDIGO_NONCE_SIZE);
                        signing_request_data->timestamp = time(NULL);

                        build_packet(packet, MSG_SIGNING_REQUEST, public_key, NULL, signing_request_data);

                        ret =
                            crypto_sign_detached(signing_request_data->signature, NULL, (unsigned char *)packet,
                                                 offsetof(packet_t, data) + offsetof(signing_request_data_t, signature),
                                                 args->signing_keys->secret);
                        if (ret) {
                            *process_return = INDIGO_ERROR_INVALID_PARAM;
                            log_fatal("[packet_handler_thread] crypto_sign_detached failed | return %d",
                                *process_return);
                            goto cleanup;
                        }

                        ret = send_packet(PORT, packet_info->address.sin_addr.s_addr, args->sockets, packet,
                                          args->flag);

                        if (ret) {
                            switch (ret) {
                                case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                                case INDIGO_ERROR_INVALID_PARAM:
                                case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                                    *process_return = ret;
                                    log_fatal("[packet_handler_thread] send_packet() failed to send signing request "
                                              "| return %d", ret);
                                    goto cleanup;
                                case INDIGO_ERROR_NO_SYS_RESOURCES: // todo: I don't think we should terminate for that
                                    break;
                                case INDIGO_ERROR_NETWORK_RESET:
                                    set_event_flag(args->flag, EF_RESET_SOCKETS);
                                    break;
                                default:
                                    break; // winlib errors go here
                            }
                            break;
                        }
                        log_debug("[packet_handler_thread] sent signing request");
                        // add signing response to expected packets
                        xsr.expiration_time = time(NULL) + EXPIRATION_TIME;
                        memcpy(xsr.nonce, signing_request_data->nonce, INDIGO_NONCE_SIZE);

                        memset(signing_request_data, 0, sizeof(signing_request_data_t));

                        if (xsr_tree->insert(xsr_tree, &xsr)) {
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            log_fatal("[packet_handler_thread] xsr_tree insert failed | return %d", *process_return);
                            goto cleanup;
                        }

                        break;
                    case MSG_SIGNING_REQUEST:
                        log_info("[packet_handler_thread] received signing request");
                        // validate the public key
                        ret = crypto_sign_verify_detached(
                            ((signing_request_data_t *)packet->data)->signature, (unsigned char *)packet,
                            offsetof(packet_t, data) + offsetof(signing_request_data_t, signature), packet->id);
                        // todo: time errors probable (same as above)
                        if (!ret) {
                            // validate the timestamp
                            curr_time = time(NULL);
                            if ((((signing_request_data_t *)packet->data)->timestamp < curr_time - 60) ||
                                (((signing_request_data_t *)packet->data)->timestamp > curr_time) + 60) {

                                log_info("[packet_handler_thread] signing request rejected due to "
                                          "expired header time stamp");
                                break;
                            }
                        }
                        else
                            break;

                        // sign the nonce and send the signature with the public key and a new nonce
                        ret = sign_buffer(args->signing_keys, ((signing_request_data_t *)packet->data)->nonce,
                                          INDIGO_NONCE_SIZE, signing_response_data->signed_nonce, NULL);
                        // can fail only dew to wrong usage
                        if (ret) {
                            *process_return = INDIGO_ERROR_INVALID_PARAM;
                            log_fatal("[packet_handler_thread] sign_buffer failed signing a peer signing request nonce "
                                      "| return %d", ret);
                            goto cleanup;
                        }

                        // create session keys
                        session_pk = malloc(crypto_kx_PUBLICKEYBYTES);
                        session_sk = malloc(crypto_kx_SECRETKEYBYTES);
                        if (!session_pk || !session_sk) {
                            free(session_pk);
                            free(session_sk);
                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                            log_fatal("[packet_handler_thread] malloc failed allocating %d+%d bytes"
                                      " for session public and private key | return %d",
                                      crypto_kx_PUBLICKEYBYTES, crypto_kx_SECRETKEYBYTES, *process_return);
                            goto cleanup;
                        }
                        sodium_mlock(session_sk, crypto_kx_SECRETKEYBYTES);

                        ret = crypto_kx_keypair(session_pk, session_sk);
                        if (ret) {
                            free(session_pk);
                            free(session_sk);
                            *process_return = INDIGO_ERROR_INVALID_PARAM;
                            log_fatal("[packet_handler_thread] crypto_kx_keypair() failed creating session keys"
                                      " | return %d", *process_return);
                            goto cleanup;
                        }

                        memcpy(signing_response_data->pkx, session_pk, crypto_kx_PUBLICKEYBYTES);
                        signing_response_data->zero = 0;

                        // if the peer is verified we don't need to send a signing request
                        ret = args->device_tree->search_pin(args->device_tree, &rdev, (void **)&found_rdev);
                        if (ret == 1) {
                            // the device is found

                            found_rdev->expiration_time = time(NULL) + EXPIRATION_TIME;
                            found_rdev->ip = packet_info->address.sin_addr.s_addr;

                            if (found_rdev->dev_state_flag & RDSF_UNVERIFIED) {
                                randombytes_buf(signing_response_data->nonce, INDIGO_NONCE_SIZE);
                                signing_response_data->sig_request = 1;

                                // insert into xsr
                                xsr.expiration_time = time(NULL) + EXPIRATION_TIME;
                                xsr.pkx = session_pk;

                                xsr.skx = session_sk;
                                memcpy(xsr.nonce, signing_response_data->nonce, INDIGO_NONCE_SIZE);
                                memcpy(xsr.id, packet->id, crypto_sign_PUBLICKEYBYTES);

                                ret = xsr_tree->insert(xsr_tree, &xsr);
                                if (ret) {

                                    args->device_tree->search_release(args->device_tree);
                                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                    log_fatal("[packet_handler_thread] xsr_tree insert failed | return %d",
                                        *process_return);
                                    goto cleanup;
                                }
                            }
                            else {
                                // we don't need to send a signature request, we erase the nonce and turn off the flag
                                memset(signing_response_data->nonce, 0, INDIGO_NONCE_SIZE);
                                signing_response_data->sig_request = 0;
                            }
                            args->device_tree->search_release(args->device_tree);
                        }
                        // in this case they found us before we received their discovery packet (if they sent any)
                        else {
                            args->device_tree->search_release(args->device_tree);
                            // add the device to the device table
                            // we detected the device (though it is unverified)
                            rdev.expiration_time = time(NULL) + EXPIRATION_TIME;
                            rdev.ip = packet_info->address.sin_addr.s_addr;
                            rdev.client_rk = NULL;
                            rdev.client_tk = NULL;
                            rdev.server_rk = NULL;
                            rdev.server_tk = NULL;
                            rdev.fsr_list = NULL;
                            rdev.fsr_count = 0;
                            memcpy(rdev.peer_pk, packet->id, crypto_sign_PUBLICKEYBYTES);
                            rdev.dev_state_flag = RDSF_UNVERIFIED; // the device is not verified

                            memcpy(known_key.key, rdev.peer_pk, crypto_sign_PUBLICKEYBYTES);
                            if (known_keys_tree->search(known_keys_tree, &known_key)) {
                                rdev.dev_state_flag |= known_key.status;
                            }
                            else {
                                rdev.dev_state_flag |= KNOWN_KEY_STATUS_UNKNOWN;
                            }

                            ret = args->device_tree->insert(args->device_tree, &rdev);
                            if (ret) {
                                free(session_pk);
                                free(session_sk);
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] device_tree insert failed inserting device"
                                          " from signing request | return %d", *process_return);
                                goto cleanup;
                            }

                            // send a nonce to verify them
                            randombytes_buf(signing_response_data->nonce, INDIGO_NONCE_SIZE);
                            signing_response_data->sig_request = 1;
                            // add signing response to expected packets
                            xsr.expiration_time = time(NULL) + EXPIRATION_TIME;
                            xsr.pkx = session_pk;
                            xsr.skx = session_sk;
                            memcpy(xsr.nonce, signing_response_data->nonce, INDIGO_NONCE_SIZE);
                            memcpy(xsr.id, packet->id, crypto_sign_PUBLICKEYBYTES);

                            if (xsr_tree->insert(xsr_tree, &xsr)) {
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] xsr_tree insert failed | return %d",
                                    *process_return);
                                goto cleanup;
                            }
                            memset(&xsr, 0, sizeof(xsr_t));
                        }
                        build_packet(packet, MSG_SIGNING_RESPONSE, public_key, NULL, signing_response_data);
                        ret =
                            crypto_sign_detached(signing_response_data->signature, NULL, (unsigned char *)packet,
                                                 offsetof(packet_t, data) + offsetof(signing_request_data_t, signature),
                                                 args->signing_keys->secret);
                        if (ret) {
                            *process_return = INDIGO_ERROR_INVALID_PARAM;
                            log_fatal("[packet_handler_thread] crypto_sign_detached() failed signing nonce for"
                                      " signing request | return %d", *process_return);
                            goto cleanup;
                        }

                        ret = send_packet(PORT, packet_info->address.sin_addr.s_addr, args->sockets, packet,
                                          args->flag);
                        if (ret) {
                            switch (ret) {
                                case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                                case INDIGO_ERROR_INVALID_PARAM:
                                case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                                    *process_return = ret;
                                    log_fatal("[packet_handler_thread] send_packet() failed sending "
                                              "signing response| return %d", *process_return);
                                    goto cleanup;
                                case INDIGO_ERROR_NO_SYS_RESOURCES: // todo: I don't think we should terminate for that
                                    break;
                                case INDIGO_ERROR_NETWORK_RESET:
                                    set_event_flag(args->flag, EF_RESET_SOCKETS);
                                    break;
                                default:
                                    break; // winlib errors go here
                            }
                        }
                        break;

                    case MSG_SIGNING_RESPONSE:
                        ret = crypto_sign_verify_detached(
                            ((signing_response_data_t *)packet->data)->signature, (unsigned char *)packet,
                            offsetof(packet_t, data) + offsetof(signing_response_data_t, signature), packet->id);
                        if (ret) {
                            log_debug("[packet_handler_thread] invalid signing response");
                            break;
                        }
                        // we don't validate signed time, since there is already a signed nonce to verify

                        memcpy(xsr.id, packet->id, crypto_sign_PUBLICKEYBYTES);
                        ret = xsr_tree->search(xsr_tree, &xsr);
                        if (ret == 0)
                            break; // if there is no expected signing response, there is nothing to process

                        // verify the signed nonce
                        ret = crypto_sign_open(nonce, NULL, ((signing_response_data_t *)packet->data)->signed_nonce,
                                               INDIGO_NONCE_SIZE + crypto_sign_BYTES, packet->id);
                        if (ret == 0) {
                            // if the nonce signed is the same as the one we sent to be signed
                            if (memcmp(xsr.nonce, nonce, INDIGO_NONCE_SIZE) == 0) {
                                // the device got verified
                                // todo: so we need to create the client and server keys, if we need to sing nonce, we
                                // create keys no xsr, otherwise use xsr
                                ret = args->device_tree->search_pin(args->device_tree, &rdev, (void **)&found_rdev);
                                /* I am not sure how we could get an expected packet for a device
                                 * that isn't in the device tree
                                 */
                                if (ret == 1) {
                                    found_rdev->expiration_time = time(NULL) + EXPIRATION_TIME;
                                    found_rdev->ip = packet_info->address.sin_addr.s_addr; // ip may have changed

                                    found_rdev->dev_state_flag |= RDSF_VERIFIED;
                                    found_rdev->dev_state_flag &= (~RDSF_UNVERIFIED);

                                    // check if we need to verify ourselves
                                    if (((signing_response_data_t *)(packet->data))->sig_request) {
                                        signing_response_data->zero = 0;
                                        signing_response_data->sig_request = 0;
                                        memset(signing_response_data->nonce, 0, INDIGO_NONCE_SIZE);

                                        ret = crypto_sign(signing_response_data->signed_nonce, NULL,
                                                          ((signing_response_data_t *)packet->data)->nonce,
                                                          INDIGO_NONCE_SIZE, args->signing_keys->secret);
                                        if (ret) {
                                            *process_return = INDIGO_ERROR_INVALID_PARAM;
                                            log_fatal("[packet_handler_thread] crypto_sign failed to sign nonce "
                                                      "for signing request | return %d", *process_return);
                                            goto cleanup;
                                        }

                                        // create session keys
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
                                            log_fatal("[packet_handler_thread] malloc failed allocating %d+%d bytes "
                                                      "for session keys | return %d",
                                                      crypto_kx_SECRETKEYBYTES,crypto_kx_SECRETKEYBYTES,
                                                      *process_return );
                                            goto cleanup;
                                        }
                                        sodium_mlock(session_sk, crypto_kx_SECRETKEYBYTES);

                                        ret = crypto_kx_keypair(session_pk, session_sk);
                                        if (ret) {
                                            free(session_pk);
                                            free(session_sk);
                                            printf("DEBUG: kx_keypair failed");
                                            fflush(stdout);
                                            *process_return = INDIGO_ERROR_INVALID_PARAM;
                                            log_fatal("[packet_handler_thread] kx_keypair failed | return %d",
                                                *process_return);
                                            goto cleanup;
                                        }
                                        ret = crypto_kx_client_session_keys(
                                            found_rdev->client_rk, found_rdev->client_tk, session_pk, session_sk,
                                            ((signing_response_data_t *)packet->data)->pkx);
                                        if (ret) {
                                            // the peer's public key is not acceptable
                                            free(session_pk);
                                            free(session_sk);
                                            break;
                                        }

                                        ret = crypto_kx_server_session_keys(
                                            found_rdev->server_rk, found_rdev->server_tk, session_pk, session_sk,
                                            ((signing_response_data_t *)packet->data)->pkx);
                                        if (ret) {
                                            // the peer's public key is not acceptable
                                            free(session_pk);
                                            free(session_sk);
                                            break;
                                        }

                                        memcpy(signing_response_data->pkx, session_pk, crypto_kx_PUBLICKEYBYTES);

                                        // we no longer need the keys
                                        free(session_pk);
                                        free(session_sk);
                                        session_pk = NULL;
                                        session_sk = NULL;

                                        build_packet(packet, MSG_SIGNING_RESPONSE, public_key, NULL,
                                                     signing_response_data);
                                        ret = crypto_sign_detached(
                                            signing_response_data->signature, NULL, (unsigned char *)packet,
                                            offsetof(packet_t, data) + offsetof(signing_response_data_t, signature),
                                            public_key);
                                        if (ret) {
                                            *process_return = INDIGO_ERROR_INVALID_PARAM;
                                            log_fatal("[packet_handler_thread] crypto_sing_detached failed signing"
                                                      " signing response packet | return %d", *process_return);
                                            goto cleanup;
                                        }
                                        ret = send_packet(PORT, packet_info->address.sin_addr.s_addr,
                                                          args->sockets, packet, args->flag);
                                        if (ret) {
                                            switch (ret) {
                                                case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                                                case INDIGO_ERROR_INVALID_PARAM:
                                                case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                                                    *process_return = ret;
                                                    log_fatal("[packet_handler_thread] send_packet failed sending"
                                                              " signing response | return &d", *process_return);
                                                    goto cleanup;
                                                case INDIGO_ERROR_NO_SYS_RESOURCES: // todo: I don't think we should
                                                                                    // terminate for that
                                                    break;
                                                case INDIGO_ERROR_NETWORK_RESET:
                                                    set_event_flag(args->flag, EF_RESET_SOCKETS);
                                                    break;
                                                default:
                                                    break; // winlib errors go here
                                            }
                                        }
                                    }
                                    else {
                                        // todo: improve error handling
                                        // create the client and server keys
                                        ret = crypto_kx_client_session_keys(
                                            found_rdev->client_rk, found_rdev->client_tk, xsr.pkx, xsr.skx,
                                            ((signing_response_data_t *)packet->data)->pkx);
                                        if (ret) {
                                            // the peer's public key is not acceptable
                                            break;
                                        }

                                        ret = crypto_kx_server_session_keys(
                                            found_rdev->server_rk, found_rdev->server_tk, xsr.pkx, xsr.skx,
                                            ((signing_response_data_t *)packet->data)->pkx);
                                        if (ret) {
                                            // the peer's public key is not acceptable
                                            break;
                                        }
                                    }
                                }

                                args->device_tree->search_release(args->device_tree);

                                // remove the expected packet
                                free(xsr.pkx);
                                free(xsr.skx);
                                xsr_tree->remove(xsr_tree, &xsr);
                            }
                        }
                        break;
                    case MSG_FILE_SENDING_REQUEST:
                        {
                            // we need permission to proceed, so we push it to the manager to handle
                            // tell the interface (ui via queue), the interface will ask the user
                            // if the user agrees, we send back a response containing the preferred session serial
                            // number if it gets accepted we receive a session_t struct via queue, and store an expected
                            // file packet

                            Q_FILE_SENDING_REQUEST *fsr;
                            Q_FILE_SENDING_REQUEST *temp_fsr = NULL;
                            file_sending_request_data_t *data;

                            if (packet->magic_number != MAGIC_NUMBER_2)
                                break;
                            fsr = malloc(sizeof(Q_FILE_SENDING_REQUEST));
                            if (!fsr) {
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] malloc failed allocating %d bytes for queue"
                                          " file sending request | return %d", *process_return);
                                goto cleanup;
                            }

                            data = (file_sending_request_data_t *)packet->data;
                            memcpy(fsr->id, packet->id, crypto_sign_PUBLICKEYBYTES);
                            fsr->file_size = data->file_size;
                            memcpy(fsr->file_name, data->file_name, NAME_MAX);
                            fsr->file_name[NAME_MAX - 1] = '\0';
                            fsr->addr = packet_info->address.sin_addr.s_addr;

                            if (args->device_tree->search_pin(args->device_tree, &rdev, (void **)&found_rdev)) {
                                if (found_rdev->dev_state_flag & KNOWN_KEY_STATUS_TOO_GOOD) {
                                    // in this case and this case only the user has specified
                                    // that this peer does not need approval
                                    ret = create_server_session(fwd, args->device_tree, args->session_tree, xfp_tree,
                                                                public_key, args->sockets, args->flag);
                                    if (ret) {
                                        // todo: create_server_session() uses send_packet() and returns its errors
                                        // todo: do more complex error handling
                                        *process_return = ret;
                                        log_fatal("[packet_handler_thread] failed to create server session "
                                                  "| return %d", *process_return);
                                        goto cleanup;
                                    }
                                    break;
                                }
                                if (found_rdev->fsr_count == MAX_SEND_REQUEST_COUNT) {
                                    // remove the last request
                                    for (Q_FILE_SENDING_REQUEST *i = found_rdev->fsr_list; i->next != NULL;
                                         i = i->next) {
                                        temp_fsr = i;
                                    }
                                    if (temp_fsr) {
                                        free(temp_fsr->next);
                                        temp_fsr->next = NULL;
                                    }
                                    (found_rdev->fsr_count)--;
                                }
                                (found_rdev->fsr_count)++;
                                temp_fsr = found_rdev->fsr_list;
                                found_rdev->fsr_list = fsr;
                                fsr->next = temp_fsr;
                            }
                            args->device_tree->search_release(args->device_tree);

                            break;
                        }
                    case MSG_FILE_SENDING_RESPONSE:
                        if (packet->magic_number != MAGIC_NUMBER_2)
                            break;
                        ret = create_client_session(packet, packet_info, args->device_tree, args->session_tree,
                                                    xfp_tree, args->send_queue);
                        if (ret) {
                            *process_return = ret;
                            log_fatal("[packet_handler_thread] failed to create client session | "
                                      "return %d", *process_return);
                            goto cleanup;
                        }
                        break;
                    case MSG_FILE_CHUNK:
                        {
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

                            // ensure that the packet was encrypted
                            if (packet->magic_number != MAGIC_NUMBER_2)
                                break;

                            // find the expected file packet node
                            memcpy(xfp.session_id.pk, packet->id, crypto_sign_PUBLICKEYBYTES);
                            xfp.session_id.serial = ((file_chunk_data_t *)packet->data)->serial;

                            ret = xfp_tree->search_pin(xfp_tree, &xfp, (void **)&found_xfp);
                            if (ret == 0) {
                                xfp_tree->search_release(xfp_tree);
                                break;
                            }
                            // if it is a client file (we expect an acception response) we don't receive it
                            if (found_xfp->packet_count == XFP_CLIENT_FILE) {
                                xfp_tree->search_release(xfp_tree);
                                break;
                            }

                            // find the session node
                            memcpy(&(session->session_id), &(xfp.session_id), sizeof(session_id_t));
                            ret = args->session_tree->search_pin(args->session_tree, session, (void **)&found_session);
                            if (ret == 0) {
                                xfp_tree->search_release(xfp_tree);
                                args->session_tree->search_release(args->session_tree);
                                break;
                            }

                            found_xfp->expiration_time = time(NULL) + EXPIRATION_TIME;

                            chunk_number = ((file_chunk_data_t *)packet->data)->chunk_number;

                            if (chunk_number < found_xfp->last_chunk) {
                                // we either received a duplicate packet or a resend
                                // in this case we don't update the packet number

                                prev_node = NULL;
                                for (range_node = found_xfp->missing_range_ll; range_node != NULL;
                                     range_node = range_node->next) {
                                    if (in_range(&(range_node->r), chunk_number))
                                        break;
                                    prev_node = range_node;
                                }
                                if (range_node == NULL)
                                    break;

                                // remove the file chunk from the range
                                if (range_node->r.start == range_node->r.end) {
                                    if (prev_node)
                                        prev_node->next = range_node->next;
                                    else {
                                        found_xfp->missing_range_ll = range_node->next;
                                    }
                                    prev_node = NULL;
                                    free(range_node);
                                    range_node = NULL;
                                }
                                else {
                                    if (chunk_number == range_node->r.start) {
                                        --(range_node->r.start);
                                    }
                                    else if (chunk_number == range_node->r.end) {
                                        --(range_node->r.end);
                                    }
                                    else {
                                        // in this case we have to split the range

                                        // here prev node is used a temporary node and not an actual previous node
                                        prev_node = malloc(sizeof(range_node_t));
                                        if (!prev_node) {
                                            // IDK do something
                                            xfp_tree->search_release(xfp_tree);
                                            args->session_tree->search_release(args->session_tree);
                                            *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                            goto cleanup;
                                        }
                                        prev_node->r.start = chunk_number + 1;
                                        prev_node->r.end = range_node->r.end;
                                        range_node->r.end = chunk_number - 1;

                                        tmp_ptr = found_xfp->missing_range_ll;
                                        found_xfp->missing_range_ll = prev_node;
                                        prev_node->next = tmp_ptr;
                                        tmp_ptr = NULL;
                                    }
                                }

                                // write the file chunk
                                if (chunk_number * PAC_DATA_PAYLOAD_BYTES < LLONG_MAX) {
                                    fseeko64(found_xfp->file, (long long)(chunk_number * PAC_DATA_PAYLOAD_BYTES),
                                             SEEK_SET);
                                }
                                else {
                                    // not very sure who owns a file bigger than 2 exbi-bytes, but why not
                                    fseeko64(found_xfp->file, LLONG_MAX, SEEK_SET);
                                    fseeko64(found_xfp->file,
                                             (long long)((chunk_number * PAC_DATA_PAYLOAD_BYTES) - LLONG_MAX),
                                             SEEK_CUR);
                                }

                                ret_val = fwrite(((file_chunk_data_t *)packet->data)->data, 1, PAC_DATA_PAYLOAD_BYTES,
                                                 found_xfp->file);
                                if (ret_val != PAC_DATA_PAYLOAD_BYTES) {
                                    ret = ferror(found_xfp->file);
                                    // TODO: here are all the errors of fwrite, handle them. these are bad errors,
                                    //       most of them
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
                                            xfp_tree->search_release(xfp_tree);
                                            args->session_tree->search_release(args->session_tree);
                                            break;
                                    }
                                    break;
                                }
                                found_session->bytes_moved += PAC_DATA_PAYLOAD_BYTES;
                                ++(found_xfp->packets_writen);

                                // check if we have received the whole file
                                if (found_xfp->packets_writen == found_xfp->packet_count) {
                                    // the missing packets should be NULL but well it does not hurt to check
                                    for (range_node_t *r = found_xfp->missing_range_ll; r != NULL; r = prev_node) {
                                        prev_node = r->next;
                                        free(prev_node);
                                    }
                                    // TODO: rename the file
                                    fclose(found_xfp->file);
                                    xfp_tree->search_release(xfp_tree);
                                    args->session_tree->search_release(args->session_tree);

                                    xfp_tree->remove(xfp_tree, &xfp);
                                    args->session_tree->remove(args->session_tree, &session);
                                    break;
                                }

                                build_packet(&temp_packet, MSG_RESEND, public_key, NULL, NULL);
                                ((transmission_control_data_t *)(temp_packet.data))->serial =
                                    ((file_chunk_data_t *)packet->data)->serial;

                                for (range_node = found_xfp->missing_range_ll; range_node != NULL;
                                     range_node = range_node->next) {
                                    // send a resend packet for each range we have
                                    ((transmission_control_data_t *)(temp_packet.data))->range = range_node->r;
                                    // send the packet
                                    ret = send_packet(PORT, packet_info->address.sin_addr.s_addr, args->sockets,
                                                      &temp_packet, args->flag);
                                    if (ret) {
                                        xfp_tree->search_release(xfp_tree);
                                        args->session_tree->search_release(args->session_tree);
                                        switch (ret) {
                                            case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                                            case INDIGO_ERROR_INVALID_PARAM:
                                            case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                                                *process_return = ret;
                                                log_fatal("[packet_handler_thread] send_packet failed "
                                                          "sending resend packets | return %d", *process_return);
                                                goto cleanup;
                                            case INDIGO_ERROR_NO_SYS_RESOURCES: // todo: I don't think we should
                                                                                // terminate for that
                                                break;
                                            case INDIGO_ERROR_NETWORK_RESET:
                                                set_event_flag(args->flag, EF_RESET_SOCKETS);
                                                break;
                                            default:
                                                break; // winlib errors go here
                                        }
                                    }
                                }
                                range_node = NULL;

                                xfp_tree->search_release(xfp_tree);
                                args->session_tree->search_release(args->session_tree);
                                break;
                            }
                            if (chunk_number > found_xfp->last_chunk) {
                                // we lost a packet, send a re-send packet

                                range_node = malloc(sizeof(range_node_t));
                                if (!range_node) {
                                    xfp_tree->search_release(xfp_tree);
                                    args->session_tree->search_release(args->session_tree);
                                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                    log_fatal("[packet_handler_thread] malloc failed allocating %d bytes for "
                                              "missing packet range node | return %d", *process_return);
                                    goto cleanup;
                                }
                                range_node->r.start = found_xfp->last_chunk;
                                range_node->r.end = chunk_number - 1;
                                tmp_ptr = found_xfp->missing_range_ll;
                                range_node->next = tmp_ptr;
                                found_xfp->missing_range_ll = range_node;
                                range_node = NULL;

                                // create the packet
                                build_packet(&temp_packet, MSG_RESEND, public_key, NULL, NULL);
                                ((transmission_control_data_t *)(temp_packet.data))->serial =
                                    ((file_chunk_data_t *)packet->data)->serial;
                                ((transmission_control_data_t *)(temp_packet.data))->range.start =
                                    found_xfp->last_chunk;
                                ((transmission_control_data_t *)(temp_packet.data))->range.end = chunk_number - 1;
                                // send the packet
                                ret = send_packet(PORT, packet_info->address.sin_addr.s_addr, args->sockets,
                                                  &temp_packet, args->flag);
                                if (ret) {
                                    xfp_tree->search_release(xfp_tree);
                                    args->session_tree->search_release(args->session_tree);
                                    switch (ret) {
                                        case INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR:
                                        case INDIGO_ERROR_INVALID_PARAM:
                                        case INDIGO_ERROR_NETWORK_SUBSYS_DOWN:
                                            *process_return = ret;
                                            log_fatal("[packet_handler_thread] send_packet failed "
                                                          "sending resend packets | return %d", *process_return);
                                            goto cleanup;
                                        case INDIGO_ERROR_NO_SYS_RESOURCES: // todo: I don't think we should terminate
                                            break;
                                        case INDIGO_ERROR_NETWORK_RESET:
                                            set_event_flag(args->flag, EF_RESET_SOCKETS);
                                            break;
                                        default:
                                            break; // winlib errors go here
                                    }
                                }
                            }

                            // set the position in the file (we are not writing necessarily at the end of the last
                            // write)
                            if (chunk_number * PAC_DATA_PAYLOAD_BYTES < LLONG_MAX) {
                                fseeko64(found_xfp->file, (long long)(chunk_number * PAC_DATA_PAYLOAD_BYTES), SEEK_SET);
                            }
                            else {
                                // not very sure who owns a file bigger than 2 exbi-bytes, but why not
                                fseeko64(found_xfp->file, LLONG_MAX, SEEK_SET);
                                fseeko64(found_xfp->file,
                                         (long long)((chunk_number * PAC_DATA_PAYLOAD_BYTES) - LLONG_MAX), SEEK_CUR);
                            }

                            ret_val = fwrite(((file_chunk_data_t *)packet->data)->data, 1, PAC_DATA_PAYLOAD_BYTES,
                                             found_xfp->file);
                            if (ret_val != PAC_DATA_PAYLOAD_BYTES) {
                                xfp_tree->search_release(xfp_tree);
                                args->session_tree->search_release(args->session_tree);
                                log_fatal("[packet_handler_thread] send_packet fwrite failed writing file chunk "
                                          "to file | return %d | errno %d", &process_return, errno);
                                ret = ferror(found_xfp->file);
                                // todo: here are all the errors of fwrite, handle them. these are bad errors, most of
                                // them
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
                            if (chunk_number >= found_xfp->last_chunk)
                                found_xfp->last_chunk = chunk_number + 1;
                            found_session->bytes_moved += PAC_DATA_PAYLOAD_BYTES;
                            ++(found_xfp->packets_writen);

                            if (found_xfp->packets_writen == found_xfp->packet_count) {
                                // the missing packets should be NULL but well it does not hurt to check
                                for (range_node_t *r = found_xfp->missing_range_ll; r != NULL; r = prev_node) {
                                    prev_node = r->next;
                                    free(prev_node);
                                }
                                // TODO: rename the file
                                fclose(found_xfp->file);
                                xfp_tree->search_release(xfp_tree);
                                args->session_tree->search_release(args->session_tree);

                                xfp_tree->remove(xfp_tree, &xfp);
                                args->session_tree->remove(args->session_tree, &session);
                                break;
                            }

                            xfp_tree->search_release(xfp_tree);
                            args->session_tree->search_release(args->session_tree);
                            break;
                        }
                    case MSG_RESEND:
                        {
                            Q_RESEND_FILE_CHUNK *qdata;
                            if (packet->magic_number != MAGIC_NUMBER_2)
                                break;
                            fprintf(stderr, "DEBUG: Resend attempted\n");
                            qdata = malloc(sizeof(Q_RESEND_FILE_CHUNK));
                            if (qdata == NULL) {
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] malloc failed allocating %d for queue resend file "
                                          "chunk data | return %d", sizeof(Q_RESEND_FILE_CHUNK), *process_return);
                                goto cleanup;
                            }
                            memcpy(&(qdata->control), packet->data, sizeof(transmission_control_data_t));
                            memcpy(qdata->session_id.pk, packet->id, crypto_sign_PUBLICKEYBYTES);
                            qdata->session_id.serial = qdata->control.serial;

                            set_event_flag(args->send_flag, EF_RESEND_FILE_CHUNK);
                            ret = queue_push(args->send_queue, qdata, QET_RESEND_FILE_CHUNK);
                            if (ret) {
                                free(qdata);
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] queue_push failed pushing resend file chunk node to "
                                          "send thread | return %d", *process_return);
                                goto cleanup;
                            }
                            break;
                        }
                    case MSG_STOP_FILE_TRANSMISSION:
                        {
                            Q_CONTROL_FILE_TRANSMISSION *qdata;
                            if (packet->magic_number != MAGIC_NUMBER_2)
                                break;
                            qdata = malloc(sizeof(Q_CONTROL_FILE_TRANSMISSION));
                            if (qdata == NULL) {
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] malloc failed allocating %d bytes for queue stop "
                                          "file transmission data  | return %d",
                                          sizeof(Q_CONTROL_FILE_TRANSMISSION), *process_return);
                                goto cleanup;
                            }
                            memcpy(&(qdata->control), packet->data, sizeof(transmission_control_data_t));
                            memcpy(qdata->session_id.pk, packet->id, crypto_sign_PUBLICKEYBYTES);
                            qdata->session_id.serial = qdata->control.serial;

                            set_event_flag(args->send_flag, EF_STOP_FILE_TRANSMISSION);
                            ret = queue_push(args->send_queue, qdata, QET_STOP_FILE_TRANSMISSION);
                            if (ret) {
                                free(qdata);
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] queue_push failed pushing stop file transmission "
                                          "node to send thread | return %d", *process_return);
                                goto cleanup;
                            }
                            break;
                        }
                    case MSG_PAUSE_FILE_TRANSMISSION:
                        {
                            Q_CONTROL_FILE_TRANSMISSION *qdata;
                            if (packet->magic_number != MAGIC_NUMBER_2)
                                break;
                            qdata = malloc(sizeof(Q_CONTROL_FILE_TRANSMISSION));
                            if (qdata == NULL) {
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] malloc failed allocating %d bytes for queue pause "
                                          "file transmission data  | return %d",
                                          sizeof(Q_CONTROL_FILE_TRANSMISSION), *process_return);
                                goto cleanup;
                            }
                            memcpy(&(qdata->control), packet->data, sizeof(transmission_control_data_t));
                            memcpy(qdata->session_id.pk, packet->id, crypto_sign_PUBLICKEYBYTES);
                            qdata->session_id.serial = qdata->control.serial;

                            set_event_flag(args->send_flag, EF_PAUSE_FILE_TRANSMISSION);
                            ret = queue_push(args->send_queue, qdata, QET_PAUSE_FILE_TRANSMISSION);
                            if (ret) {
                                free(qdata);
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] queue_push failed pushing pause file transmission "
                                          "node to send thread | return %d", *process_return);
                                goto cleanup;
                            }
                            break;
                        }
                    case MSG_CONTINUE_FILE_TRANSMISSION:
                        {
                            Q_CONTROL_FILE_TRANSMISSION *qdata;
                            if (packet->magic_number != MAGIC_NUMBER_2)
                                break;
                            qdata = malloc(sizeof(Q_CONTROL_FILE_TRANSMISSION));
                            if (qdata == NULL) {
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] malloc failed allocating %d bytes for queue "
                                          "continue file transmission data  | return %d",
                                          sizeof(Q_CONTROL_FILE_TRANSMISSION), *process_return);
                                goto cleanup;
                            }
                            memcpy(&(qdata->control), packet->data, sizeof(transmission_control_data_t));
                            memcpy(qdata->session_id.pk, packet->id, crypto_sign_PUBLICKEYBYTES);
                            qdata->session_id.serial = qdata->control.serial;

                            set_event_flag(args->send_flag, EF_CONTINUE_FILE_TRANSMISSION);
                            ret = queue_push(args->send_queue, qdata, QET_CONTINUE_FILE_TRANSMISSION);
                            if (ret) {
                                free(qdata);
                                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_fatal("[packet_handler_thread] queue_push failed pushing continue file "
                                          "transmission node to send thread | return %d", *process_return);
                                goto cleanup;
                            }
                            break;
                        }
                    case MSG_IP_CHANGE:
                        if (packet->magic_number != MAGIC_NUMBER_2)
                            break;
                        log_debug("[packet_handler_thread] received ip change");
                        break;
                    case MSG_ERR:
                        log_debug("[packet_handler_thread] received error");
                        break;
                    default:
                        printf("\noops...\n");
                        break;
                }

                // we no longer need the packet
                mempool_free(args->mempool, packet);
                packet = NULL;
                packet_info = NULL;
            }
            else if (node->type == QET_SESSION_START) {
                // they sent us a send request and the user said yes
                fwd = node->data;
                ret = create_server_session(fwd, args->device_tree, args->session_tree, xfp_tree, public_key,
                                            args->sockets, args->flag);
                free(fwd);
                if (ret) {
                    // todo: create_server_session() uses send_packet() and returns its errors
                    // todo: do more complex error handling
                    *process_return = ret;
                    log_fatal("[packet_handler_thread] create_server_session failed creating session | return %d",
                        *process_return);
                    goto cleanup;
                }
                destroy_qnode(node);
                node = NULL;
            }
            else if (node->type == QET_EXPECT_SEND_RESPONSE) {
                Q_EXPECT_SEND_RESPONSE *qe = (Q_EXPECT_SEND_RESPONSE *)node->data;
                // we sent a request to send a file, and we expect a response to that request
                memset(&xfp, 0, sizeof(xfp_t));
                memcpy(&(xfp.session_id), &(qe->session_id), sizeof(session_id_t));
                xfp.file = qe->file;
                xfp.expiration_time = time(NULL) + EXPIRATION_TIME;
                xfp.packet_count = XFP_CLIENT_FILE;
                free(node->data);
                destroy_qnode(node);
                node = NULL;

                ret = xfp_tree->insert(xfp_tree, &xfp);
                if (ret) {
                    fclose(xfp.file);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    log_fatal("[packet_handler_thread] xfp_tree insert failed inserting client file| return %d",
                        *process_return);
                    goto cleanup;
                }
            }
            else {
                // probably an error but good to check
                destroy_qnode(node);
                node = NULL;
                continue;
            }
        }

        /*  here if there are more packets in the queue we go back up to process them,
         *  but we don't want to have ghost devises and ghost expected packets
         *  so in case there are too many packets we refresh the list once per 10 packets processed
         */

        if (iterations_until_cleanup > 0) {
            iterations_until_cleanup--;
            if (!queue_is_empty(args->queue))
                continue;
        }
        else
            iterations_until_cleanup = 10;

        /////////////////////////////////////////
        ///     phase 2: update the trees     ///
        /////////////////////////////////////////
        curr_time = time(NULL);

        // update the xsr tree
        ret = new_tree_iterator(xsr_tree, &xsr_iterator);
        if (ret) {
            *process_return = ret;
            log_fatal("[packet_handler_thread] failed to create xsr iterator | return %d", *process_return);
            goto cleanup;
        }
        if (xsr_iterator) {
            while (tree_has_next(xsr_iterator)) {
                tree_next(xsr_iterator, (void **)&found_xsr);
                time_diff = found_xsr->expiration_time - curr_time;
                if (time_diff < 0) {
                    memcpy(&xsr, found_xsr, sizeof(xsr_t));
                    ret = xsr_tree->remove(xsr_tree, &xsr);
                    if (ret) {
                        // todo: i dont remember what errors it returns
                        //  it is not an error about the node not existing,
                        //  that would indicate an implementation error
                        free_tree_iterator(&xsr_iterator);
                        *process_return = ret;
                        log_fatal("[packet_handler_thread] xsr remove failed | return %d", *process_return);
                        goto cleanup;
                    }
                }
                else {
                    // branchless minimum
                    lowest_time = time_diff + ((lowest_time - time_diff) &
                                               ((lowest_time - time_diff) >> (sizeof(time_t) * CHAR_BIT - 1)));
                }
            }
            free_tree_iterator(&xsr_iterator);
        }

        // update the xfp tree
        /*TODO: there is a case where we delete the xfp but the session persists,
         *      since xfp and session will merge, this is not that important for now
         */
        ret = new_tree_iterator(xfp_tree, &xfp_iterator);
        if (ret) {
            *process_return = ret;
            log_fatal("[packet_handler_thread] failed to create xfp iterator | return %d", *process_return);
            goto cleanup;
        }
        if (xfp_iterator) {
            while (tree_has_next(xfp_iterator)) {
                tree_next(xfp_iterator, (void **)&found_xfp);
                time_diff = found_xfp->expiration_time - curr_time;
                if (time_diff < 0) {
                    memcpy(&xfp, found_xfp, sizeof(xfp_t));
                    ret = xfp_tree->remove(xfp_tree, &xfp);
                    if (ret) {
                        // todo: i dont remember what errors it returns
                        //  it is not an error about the node not existing,
                        //  that would indicate an implementation error
                        free_tree_iterator(&xfp_iterator);
                        *process_return = ret;
                        log_fatal("[packet_handler_thread] xfp remove failed | return %d", *process_return);
                        goto cleanup;
                    }
                }
                else {
                    // branchless minimum
                    lowest_time = time_diff + ((lowest_time - time_diff) &
                                               ((lowest_time - time_diff) >> (sizeof(time_t) * CHAR_BIT - 1)));
                }
            }
            free_tree_iterator(&xfp_iterator);
        }

        // update the device tree
        tree_lock(args->device_tree);
        ret = new_tree_iterator(args->device_tree, &rdev_iterator);
        if (ret) {
            *process_return = ret;
            log_fatal("[packet_handler_thread] failed to create xsr iterator | return %d", *process_return);
            goto cleanup;
        }
        if (rdev_iterator) {
            while (tree_has_next(rdev_iterator)) {
                tree_next(rdev_iterator, (void **)&found_rdev);
                time_diff = found_rdev->expiration_time - curr_time;
                if (time_diff < 0) {
                    memcpy(&rdev, found_rdev, sizeof(xfp_t));
                    // if we use thread safe remove function (tree->remove), we create a deadlock.
                    // and we cant just unlock the tree because the iterator may not remain valid.
                    ret = avl_delete_unlocked(args->device_tree, &rdev);
                    if (ret) {
                        // todo: i dont remember what errors it returns
                        //  it is not an error about the node not existing,
                        //  that would indicate an implementation error
                        free_tree_iterator(&rdev_iterator);
                        *process_return = ret;
                        log_fatal("[packet_handler_thread] device_tree remove failed | return %d", *process_return);
                        goto cleanup;
                    }
                }
                else {
                    // branchless minimum
                    lowest_time = time_diff + ((lowest_time - time_diff) &
                                               ((lowest_time - time_diff) >> (sizeof(time_t) * CHAR_BIT - 1)));
                }
            }
            free_tree_iterator(&rdev_iterator);
        }
        tree_unlock(args->device_tree);

        // there is no need to sleep if there is more stuff to do
        if (!queue_is_empty(args->queue))
            continue;

        /////////////////////////////////////////////
        ///  phase 3: wait a little and go again  ///
        /////////////////////////////////////////////
        clock_gettime(CLOCK_REALTIME, &timespec);
        timespec.tv_sec += lowest_time;

        pthread_mutex_lock(&args->flag->mutex);
        pthread_cond_timedwait(&args->flag->cond, &args->flag->mutex, &timespec);
        pthread_mutex_unlock(&args->flag->mutex);
    }

    free_tree(xsr_tree);
    free_tree(xfp_tree);
    free_tree(known_keys_tree);
    free(signing_request_data);
    free(signing_response_data);
    free(file_sending_request_data);
    free(file_sending_response_data);
    log_info("[packet_handler_thread] thread successful exit");
    return process_return;

cleanup:
    destroy_qnode(node);
    free_tree(xsr_tree);
    free_tree(xfp_tree);
    free_tree(known_keys_tree);
    free(signing_request_data);
    free(signing_response_data);
    free(file_sending_request_data);
    free(file_sending_response_data);

    set_event_flag(args->flag, EF_TERMINATION);
    set_event_flag(args->wake, EF_WAKE_MANAGER);
    log_info("[packet_handler_thread] thread exit with errors");
    return process_return;
}

// cmp functions (helpers)
int cmp_xsr(void *s1, void *s2) { return memcmp(((xsr_t *)s1)->id, ((xsr_t *)s2)->id, crypto_kx_PUBLICKEYBYTES); }

int cmp_xfp(void *s1, void *s2)
{
    return memcmp(&((xfp_t *)s1)->session_id, &((xfp_t *)s2)->session_id,
                  (sizeof(uint64_t) + crypto_sign_PUBLICKEYBYTES));
}

int create_server_session(Q_FILE_SENDING_REQUEST *fwd, tree_t *dev_tree, tree_t *session_tree, tree_t *xfp_tree,
                          unsigned char pk[crypto_sign_PUBLICKEYBYTES], socket_ll *sockets, EFLAG *flag)
{
    // they sent us a send request and the user said yes

    int ret;
    remote_device_t rdev;
    packet_t *packet = NULL;
    session_t *session = NULL;
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    file_sending_response_data_t file_sending_response_data = {0};
    xfp_t xfp;
    char file_name[2 * sizeof(session_id_t) + 1 + 9] = INDIGO_TEMP_DIR;
    char xpath[PATH_MAX];
    char *initial_cwd;

    // there is no point to receive a file of 0 bytes, I mean we don't transfer metadata, so I guess there is no point
    if (fwd->file_size == 0) {
        ret = 1;
        log_error("[create_server_session] file size is 0 | return %d", ret);
        goto cleanup;
    }
    memcpy(&(rdev.peer_pk), fwd->id, crypto_sign_PUBLICKEYBYTES);
    ret = dev_tree->search(dev_tree, &rdev);
    if (ret == 0) {
        log_warn("[create_server_session] peer not found in device tree. Can not create session");
        return INDIGO_ERROR_INVALID_PEER_PARAM;
    }

    // necessary allocations
    packet = malloc(sizeof(struct udp_packet_t));
    session = malloc(sizeof(session_t));
    if (!session || !packet) {
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[create_server_session] malloc failed allocating packet %dB and session %dB | return %d",
            sizeof(struct udp_packet_t),sizeof(session_t), ret);
        goto cleanup;
    }

    // zero out the xfp. Not sure if this is necessary, probably will be optimized out by the compiler
    memset(&xfp, 0, sizeof(xfp_t));
    // create the file we will write to
    for (int i = 0; i < crypto_sign_PUBLICKEYBYTES; ++i) {
        sprintf(file_name + (2 * i), "%02x", (xfp.session_id.pk)[i]);
    }
    sprintf(file_name, "%016lx", xfp.session_id.serial);
    file_name[2 * sizeof(session_id_t)] = '\0';

    initial_cwd = g_get_current_dir();
    get_source_dir(xpath);
    chdir(xpath);

    xfp.file = fopen(file_name, "wb");
    if (!xfp.file) {
        chdir(initial_cwd);
        g_free(initial_cwd);
        ret = INDIGO_ERROR_CAN_NOT_OPEN_FILE;
        log_error("[create_server_session] failed opening file %s for receiving | return %d |errno %d ",
            file_name, ret, errno);
        goto cleanup;
    }
    chdir(initial_cwd);
    g_free(initial_cwd);

    // check if the serial is valid
    if (rdev.last_fid >= fwd->serial) {
        // reject the session, no bargaining, if the serial cant be used, then no session
        ret = INDIGO_ERROR_INVALID_PEER_PARAM;
        goto cleanup;
    }
    file_sending_response_data.serial = fwd->serial;
    // todo: increment the last_serial in rdev.

    // todo: i think this nonce is for the encryption, but i cant remember
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    build_packet(packet, MSG_FILE_SENDING_RESPONSE, pk, nonce, &file_sending_response_data);
    ret = encrypt_packet(packet, rdev.server_tk, nonce);
    if (ret) {
        log_error("[create_server_session] encrypt packet failed | return %d", ret);
        goto cleanup;
    }

    ret = send_packet(PORT, fwd->addr, sockets, packet, flag);
    if (ret) {
        log_error("[create_server_session] send_packet failed sending file sending response| return %d", ret);
        goto cleanup; // it's up to the caller to handle these errors, we cant do anything
    }

    free(packet);
    packet = NULL;

    // create expected file packets
    xfp.expiration_time = time(NULL) + EXPIRATION_TIME;
    xfp.packet_count = (uint64_t)ceil((double)(fwd->file_size) / (double)(1 << 10));
    xfp.packets_writen = 0;
    xfp.last_chunk = 0;
    xfp.session_id.serial = file_sending_response_data.serial;
    xfp.missing_range_ll = NULL;
    memcpy(xfp.session_id.pk, fwd->id, crypto_sign_PUBLICKEYBYTES);

    ret = xfp_tree->insert(xfp_tree, &xfp);
    if (ret) {
        log_error("[create_server_session] xfp insert failed");
        goto cleanup;
    }

    memcpy(&(session->session_id), &(xfp.session_id), sizeof(session_id_t));
    session->bytes_moved = 0;
    session->start_time = time(NULL);
    session->status_flags = 0;
    session->port = PORT;
    session->ip = fwd->addr;

    ret = session_tree->insert(session_tree, session);
    if (ret) {
        log_error("[create_server_session] session insert failed");
        goto cleanup;
    }

    return 0;

cleanup:
    free(packet);
    free(session);
    return ret;
}

int create_client_session(const packet_t *const packet, const packet_info_t *const packet_info, tree_t *dev_tree,
                          tree_t *session_tree, tree_t *xfp_tree, QUEUE *send_queue)
{
    // we got their one time public key, and confirmation to proceed
    // we calculate the send key
    // tell the sending thread to start sending the file
    int ret;
    remote_device_t rdev;
    session_t *session = NULL;
    active_file_t *tmp_active_file = NULL;
    xfp_t xfp;

    // check if the peer is in the device tree (if they are not, we shouldn't create a session)
    ret = dev_tree->search(dev_tree, &rdev);
    if (ret == 0)
        goto cleanup;

    // add an expected file packet (xfp) for this session
    memcpy(&(xfp.session_id.pk), packet->id, crypto_sign_PUBLICKEYBYTES);
    xfp.session_id.serial = ((file_sending_response_data_t *)(packet->data))->serial;
    /*We sent a packet with a seral to begin a session.
     * we created an xfp with that serial. (don't worry there is an expiration time, it will not stay forever).
     * we expect a response with the serial we sent (it is an identifier for that session that is being created).
     * If we don't receive a response, nothing should happen.
     */
    // if the session id is not found, then the returned serial is not valid, and the session is rejected
    ret = xfp_tree->search(xfp_tree, &xfp);
    if (ret == 0) {
        ret = INDIGO_ERROR_PEER_NOT_FOUND;
        log_warn("[create_client_session] peer not found in expected files tree. Can not create client session");
        goto cleanup;
    }

    // if they sent us a serial of a file we are receiving then we reject.
    //(an attacker or a badly writen mod, either way me not happy).
    if (xfp.packet_count != XFP_CLIENT_FILE) {
        // we don't goto cleanup here. we don't want to remove an active file
        log_warn("[create_client_session] peer not found in expected files tree. Can not create client session");
        return INDIGO_ERROR_INVALID_PEER_PARAM;
    }

    // necessary allocations
    tmp_active_file = malloc(sizeof(active_file_t));
    session = malloc(sizeof(session_t));
    if (!session || !tmp_active_file) {
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        log_error("[create_client_session] malloc failed allocating %d+%dB for active file and session | return %d",
            sizeof(active_file_t),sizeof(session_t), ret);
        goto cleanup;
    }

    memcpy(&(session->session_id), &(xfp.session_id), sizeof(session_id_t));
    session->bytes_moved = 0;
    session->start_time = time(NULL);
    session->status_flags = 0;
    session->port = PORT;
    session->ip = packet_info->address.sin_addr.s_addr;

    ret = session_tree->insert(session_tree, session);
    if (ret) {
        log_error("[create_client_session] session insert failed | return %d", ret);
        goto cleanup;
    }

    tmp_active_file->fd = xfp.file; // todo xfp should contain a file descriptor, as for now it is not initialized
    tmp_active_file->counter = 0;
    tmp_active_file->next = NULL;
    memcpy(tmp_active_file->session_id.pk, packet->id, crypto_sign_PUBLICKEYBYTES);
    tmp_active_file->session_id.serial = ((file_sending_response_data_t *)(packet->data))->serial;

    ret = queue_push(send_queue, tmp_active_file, QET_SEND_FILE);
    if (ret != 0) {
        log_error("[create_client_session] queue_push failed pushing active file to send queue | return %d", ret);
        goto cleanup;
    }

    xfp_tree->remove(xfp_tree, &xfp);
    return 0;

cleanup:
    free(tmp_active_file);
    free(session);
    xfp_tree->remove(xfp_tree, &xfp);
    return ret;
}