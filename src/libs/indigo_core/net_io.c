//
// Created by Constantin on 26/01/2026.
//
#include <indigo_core/net_io.h>
#include <stdio.h>
#include <indigo_errors.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>


#include "buffer.h"
#include "crypto_utils.h"
#include "indigo_core.h"
#include <indigo_types.h>

//////////////////////////////////////////////////////
///                                                ///
///                  IO_FUNCTIONS                  ///
///                                                ///
//////////////////////////////////////////////////////

//todo: continue error handling from here

//todo: OVERRIDE_IO is not handled correctly check implementation
int send_discovery_packets(
    const int port,
    const uint32_t multicast_addr,
    socket_ll *sockets,
    EFLAG *flag,
    const uint32_t pCount,
    const int32_t msec,
    signing_key_pair_t * sign_key_pair,
    wchar_t username[MAX_USERNAME_LEN]) {
    uint8_t restart = 0;
    //temporary variables for memory allocation
    SEND_INFO temp_info = {0};
    SEND_INFO *sInfo = NULL;
    size_t infolen = 0;
    void *temp;

    HANDLE *handles = NULL;
    size_t hCount = 0;

    int ret_val;
    DWORD wait_ret;
    uint32_t flag_val = 0;
    const int32_t temp_math = msec % 1000;

    struct timespec ts;
    time_t curr_time;

    packet_t packet;
    init_packet_data_t packet_data;
    int routine_ret = 0;

    build_packet(&packet, MSG_INIT_PACKET, sign_key_pair->public, NULL, NULL);
    wcsncpy(packet_data.username, username, MAX_USERNAME_LEN);


    while (1) {
        restart = 0;
        pthread_mutex_lock(&sockets->mutex);
        for (socket_node *sock = sockets->head; sock != NULL; sock = sock->next){
            //for every socket we send we allocate the fields of SEND_INFO (they can't be in the stack)
            temp = calloc(1,sizeof(struct sockaddr_in));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.dest = temp;

            temp_info.dest->sin_family = AF_INET;
            temp_info.dest->sin_addr.S_un.S_addr = multicast_addr;
            temp_info.dest->sin_port = port;

            temp = malloc(sizeof(WSABUF));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.buf = temp;
            temp_info.buf->buf = NULL;

            temp = malloc(sizeof(packet_t));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.buf->buf = temp;
            memcpy(temp_info.buf->buf, &packet, sizeof(packet_t));
            temp_info.buf->len = sizeof(packet_t);

            temp = malloc(sizeof(OVERLAPPED));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.overlapped = temp;
            temp_info.overlapped->hEvent = WSACreateEvent();
            if (temp_info.overlapped->hEvent == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "WSACreateEvent() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }

            temp = malloc(sizeof(DWORD));
            if (temp == NULL) {
                fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            temp_info.bytes = temp;

            temp_info.socket = sock->sock;

            //we resize the sInfo array to hold one more send info
            temp = realloc(sInfo, sizeof(SEND_INFO) * (infolen + 1));
            if (temp == NULL) {
                fprintf(stderr, "realloc() failed in send_discovery_packets()\n");
                pthread_mutex_unlock(&sockets->mutex);
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }
            sInfo = temp;
            memcpy(sInfo + infolen, &temp_info, sizeof(SEND_INFO));
            infolen++;
            memset(&temp_info, 0, sizeof(SEND_INFO));//so that we dont double free

            flag_val = get_event_flag(flag);
            if (flag_val & EF_OVERRIDE_IO) {
                //since there is OVERRIDE_IO the sockets we got are not valid (they are being currently updated)
                //free the allocated resources and exit the loop
                free_send_info(&temp_info);
                for (size_t i = 0; i < infolen; i++) {
                    free_send_info(&sInfo[i]);
                }
                free(handles);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                restart = 1;
                break;
            }
            if (flag_val & EF_TERMINATION) goto cleanup;

            curr_time = time(NULL);
            //todo this is wrong because we sign the whole data and not just the timestamp
            crypto_sign(packet_data.signed_time
                              ,NULL
                              ,(unsigned char *)&curr_time
                              ,sizeof(time_t)
                              ,sign_key_pair->secret);


            ret_val = WSASendTo(sock->sock,
                sInfo[infolen - 1].buf,
                1,
                sInfo[infolen - 1].bytes,
                MSG_DONTROUTE,
                (struct sockaddr *)(sInfo[infolen - 1].dest),
                sizeof(struct sockaddr),
                sInfo[infolen - 1].overlapped,
                NULL);

            if (ret_val == SOCKET_ERROR) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n",WSAGetLastError());
                    pthread_mutex_unlock(&sockets->mutex);
                    routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                    goto cleanup;
                }
            }
        }
        pthread_mutex_unlock(&sockets->mutex);

        if (restart) continue;

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (msec - temp_math)/1000;
        ts.tv_nsec += temp_math * 1000000;

        flag_val = get_event_flag(flag);
        if (flag_val & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            for (size_t i = 0; i < infolen; i++) {
                free_send_info(&sInfo[i]);
            }
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
            continue;
        }
        if (flag_val & EF_TERMINATION) goto cleanup;

        pthread_mutex_lock(&flag->mutex);
        pthread_cond_timedwait(&flag->cond, &flag->mutex, &ts);

        if (flag->event_flag & EF_TERMINATION) goto cleanup;
        if (flag->event_flag & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            for (size_t i = 0; i < infolen; i++) {
                free_send_info(&sInfo[i]);
            }
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
            continue;
        }

        pthread_mutex_unlock(&flag->mutex);

        //create the handle array to use to check if the io has finished
        if(create_handle_array_from_send_info(sInfo, infolen, &handles, &hCount)) {
            fprintf(stderr, "create_handle_array_from_send_info() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        //check if the io is finished
        wait_ret = WSAWaitForMultipleEvents(hCount,handles,TRUE,100, FALSE);
        if (wait_ret == WSA_WAIT_FAILED) {
            fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
            routine_ret = INDIGO_ERROR_WINLIB_ERROR ;
            goto cleanup;
        }
        if (wait_ret == WSA_WAIT_TIMEOUT) {
            for (size_t i = 0; i < hCount; i++) {
                wait_ret = WaitForSingleObject(handles[i], 0);
                if (wait_ret == WAIT_OBJECT_0) continue;

                if (wait_ret == WAIT_FAILED) {
                    fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                    goto cleanup;
                }

                if (wait_ret == WAIT_TIMEOUT) {
                    CancelIo(handles[i]);
                }
            }
        }

        if (sInfo == NULL) goto cleanup;

        //send the rest of the packets based on the previous SEND_INFO allocations
        for (size_t i = 0; i < pCount - 1; i++) {
            for (size_t j = 0; j < infolen; j++) {
                WSAResetEvent(handles[j]);

                ret_val = WSASendTo(sInfo[j].socket,
                sInfo->buf,
                1,
                sInfo->bytes,
                MSG_DONTROUTE,
                (struct sockaddr *)(sInfo->dest),
                sizeof(struct sockaddr),
                sInfo->overlapped,
                NULL);

                if (ret_val == SOCKET_ERROR) {
                    if (WSAGetLastError() != WSA_IO_PENDING) {
                        fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n",WSAGetLastError());
                        pthread_mutex_unlock(&sockets->mutex);

                        routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                        goto cleanup;
                    }
                }
            }

            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (msec - temp_math)/1000;
            ts.tv_nsec += temp_math * 1000000;

            flag_val = get_event_flag(flag);
            if (flag_val & EF_OVERRIDE_IO) {
                free_send_info(&temp_info);
                for (size_t l = 0; l < infolen; l++) {
                    free_send_info(&sInfo[l]);
                }
                free(handles);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                break;
            }
            if (flag_val & EF_TERMINATION) goto cleanup;

            pthread_mutex_lock(&flag->mutex);
            pthread_cond_timedwait(&flag->cond, &flag->mutex, &ts);

            if (flag->event_flag & EF_TERMINATION) goto cleanup;
            if (flag->event_flag & EF_OVERRIDE_IO) {
                free_send_info(&temp_info);
                for (size_t l = 0; l < infolen; l++) {
                    free_send_info(&sInfo[l]);
                }
                free(handles);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                break;
            }

            pthread_mutex_unlock(&flag->mutex);

            if(create_handle_array_from_send_info(sInfo, infolen, &handles, &hCount)) {
                fprintf(stderr, "create_handle_array_from_send_info() failed in send_discovery_packets()\n");
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }

            wait_ret = WSAWaitForMultipleEvents(hCount,handles,TRUE,100, FALSE);
            if (wait_ret == WSA_WAIT_FAILED) {
                fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                goto cleanup;
            }
            if (wait_ret == WSA_WAIT_TIMEOUT) {
                for (size_t k = 0; k < hCount; k++) {
                    wait_ret = WaitForSingleObject(handles[i], 0);
                    if (wait_ret == WAIT_OBJECT_0) continue;

                    if (wait_ret == WAIT_FAILED) {
                        fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                        routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                        goto cleanup;
                    }

                    if (wait_ret == WAIT_TIMEOUT) {
                        CancelIo(handles[k]);
                    }
                }
            }
        }
        if (flag_val & EF_OVERRIDE_IO) continue;


        free_send_info(&temp_info); // temporary
        for (size_t i = 0; i < infolen; i++) {
            free_send_info(&sInfo[i]);
        }
        free(handles);
        return 0;
    }
    cleanup:

    flag_val = get_event_flag(flag);
    if (flag_val & EF_TERMINATION) return -1;

    free_send_info(&temp_info);
    for (size_t i = 0; i < infolen; i++) {
        free_send_info(&sInfo[i]);
    }
    free(handles);
    return routine_ret;
}

int register_single_receiver(SOCKET sock, RECV_INFO **info, mempool_t* mempool) {
    RECV_INFO *temp_info;

    int recv_ret;

    if (!info || !mempool) {
        fprintf(stderr, "register_single_receiver called with info or mempool NULL\n");
        return -1;
    }

    //if we are not provided an allocated RECV_INFO (most likely on first use)
    if (*info == NULL) {

        if (allocate_recv_info(&temp_info, mempool)) {
            fprintf(stderr, "allocate_recv_info() failed in send_discovery_packets()\n");
            return 1;
        }

        temp_info->socket = sock;
        *(temp_info->flags) = 0;


        recv_ret = WSARecvFrom(sock,
            temp_info->buf,
            1,
            temp_info->bytes_recv,
            temp_info->flags,
            temp_info->source,
            temp_info->fromLen,
            temp_info->overlapped,
            NULL);

        if (recv_ret == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr,"WSARecvFrom() failed in register_single_discovery_receiver(): %d\n", WSAGetLastError());
                free_recv_info(temp_info, mempool);
                free(temp_info);
                return 1;
            }
        }
        *info = temp_info;
    }
    else {
        //if we are provided an allocated RECV_INFO (most likely from previous use)
        recv_ret = WSARecvFrom(sock,
            (*info)->buf,
            1,
            (*info)->bytes_recv,
            (*info)->flags,
            (*info)->source,
            (*info)->fromLen,
            (*info)->overlapped,
            NULL);

        if (recv_ret == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr,"WSARecvFrom() failed in register_single_discovery_receiver(): %d\n", WSAGetLastError());
                return 1;
            }
        }
    }

    return 0;
}

int register_multiple_receivers(socket_ll *sockets, RECV_ARRAY *info, mempool_t* mempool, EFLAG *flag) {
    void *temp = NULL;
    RECV_INFO *tempinf = NULL;

    uint32_t flag_val = 0;

    int recv_ret;
    //in case we get an override flag we restart
    while (1) {
        flag_val = 0;

        info->array = NULL;
        info->size = 0;

        pthread_mutex_lock(&sockets->mutex);
        //for every socket available
        for (socket_node *sock = sockets->head; sock != NULL; sock = sock->next) {
            temp = realloc(info->array, (info->size + 1) * sizeof(RECV_INFO));
            if (temp == NULL) {
                fprintf(stderr, "realloc() failed in register_multiple_discovery_receivers()\n");
                pthread_mutex_unlock(&sockets->mutex);
                return 1;
            }
            info->array = temp;

            if (allocate_recv_info_fields(info->array + info->size, mempool)) {
                fprintf(stderr, "allocate_recv_info_fields() failed in register_multiple_discovery_receivers()\n");
                temp = realloc(info->array, (info->size) * sizeof(RECV_INFO)); // we decrease the size by one
                if (temp == NULL) {
                    pthread_mutex_unlock(&sockets->mutex);
                    fprintf(stderr, "realloc() failed in register_multiple_discovery_receivers()\n");
                    return 1;
                }
                info->array = temp;
                pthread_mutex_unlock(&sockets->mutex);
                return 1;
            }

            tempinf = info->array + info->size;

            tempinf->socket = sock->sock;
            *(tempinf->flags) = 0;

            info->size++;

            flag_val = get_event_flag(flag);
            if (flag_val & EF_OVERRIDE_IO) {
                free_recv_array(info, mempool);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                break;
            }
            if (flag_val & EF_TERMINATION) {
                pthread_mutex_unlock(&sockets->mutex);
                return -1;
            }

            recv_ret = WSARecvFrom(sock->sock,
                tempinf->buf,
                1,
                tempinf->bytes_recv,
                tempinf->flags,
                tempinf->source,
                tempinf->fromLen,
                tempinf->overlapped,
                NULL);

            if (recv_ret == SOCKET_ERROR) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    fprintf(stderr,"WSARecvFrom() failed in register_multiple_discovery_receivers(): %d\n", WSAGetLastError());
                    pthread_mutex_unlock(&sockets->mutex);
                    return 1;
                }
            }
        }
        pthread_mutex_unlock(&sockets->mutex);
        if (flag_val & EF_OVERRIDE_IO) {continue;}
        return 0;
    }
}


int send_packet(const int port, const uint32_t addr, socket_ll* sockets, const packet_t* const packet, EFLAG *flag) {
    SEND_INFO temp_info;
    SOCKET sock;
    void *temp;
    int ret_val;
    DWORD wait_ret;
    uint32_t flag_val = 0;
    int routine_ret = 0;

    while (1) {
        temp = calloc(1,sizeof(struct sockaddr_in));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.dest = temp;

        temp_info.dest->sin_family = AF_INET;
        temp_info.dest->sin_addr.S_un.S_addr = addr;
        temp_info.dest->sin_port = port;

        temp = malloc(sizeof(WSABUF));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.buf = temp;
        temp_info.buf->buf = NULL;

        temp = malloc(sizeof(packet_t));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.buf->buf = temp;
        memcpy(temp_info.buf->buf, packet, sizeof(packet_t));
        temp_info.buf->len = sizeof(packet_t);

        temp = malloc(sizeof(OVERLAPPED));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.overlapped = temp;
        temp_info.overlapped->hEvent = WSACreateEvent();
        if (temp_info.overlapped->hEvent == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "WSACreateEvent() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }

        temp = malloc(sizeof(DWORD));
        if (temp == NULL) {
            fprintf(stderr, "malloc() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        temp_info.bytes = temp;


        flag_val = get_event_flag(flag);
        if (flag_val & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
        }
        if (flag_val & EF_TERMINATION) goto cleanup;

        pthread_mutex_lock(&sockets->mutex);
        sock = ip_to_socket(addr, sockets);
        pthread_mutex_unlock(&sockets->mutex);

        ret_val = WSASendTo(sock,
            temp_info.buf,
            1,
            temp_info.bytes,
            MSG_DONTROUTE,
            (struct sockaddr *)(temp_info.dest),
            sizeof(struct sockaddr),
            temp_info.overlapped,
            NULL);

        if (ret_val == SOCKET_ERROR) {
            ret_val = WSAGetLastError();
            if (ret_val != WSA_IO_PENDING) {
                fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n",ret_val);
                switch (ret_val) {
                    case WSAEACCES:
                        routine_ret = INDIGO_ERROR_ACCESS_DENIED;
                        break;
                    case WSAEADDRNOTAVAIL:
                    case WSAEAFNOSUPPORT:
                    case WSAEDESTADDRREQ:
                    case WSAEFAULT:
                    case WSAEHOSTUNREACH:
                    case WSAEINVAL:
                    case WSAEMSGSIZE:
                        routine_ret = INDIGO_ERROR_INVALID_PARAM;
                        break;
                    case WSAENETDOWN:
                        routine_ret = INDIGO_ERROR_NETWORK_SUBSYS_DOWN;
                        break;
                    case WSAENETRESET:
                    case WSAESHUTDOWN:
                        routine_ret = INDIGO_ERROR_NETWORK_RESET;
                        break;
                    case WSAENOBUFS:
                        routine_ret = INDIGO_ERROR_NO_SYS_RESOURCES;
                        break;
                    default:
                        fprintf(stderr, "HOW THE FUCK DID THIS HAPPEN\n");
                        break;
                }
                goto cleanup;
            }
        }

        wait_ret = WaitForSingleObject(temp_info.overlapped->hEvent, 100);
        if (wait_ret == WAIT_FAILED) {
            fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
            routine_ret = INDIGO_ERROR_WINLIB_ERROR; //todo: change to something that can be handled, i really dont know what it should be
            goto cleanup;
        }
        if (wait_ret == WAIT_TIMEOUT) {
            wait_ret = WaitForSingleObject(temp_info.overlapped->hEvent, 150);
            //if (wait_ret == WAIT_OBJECT_0) continue; //todo: check for correctness, why should this line exist

            if (wait_ret == WAIT_FAILED) {
                fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                goto cleanup;
            }

            if (wait_ret == WAIT_TIMEOUT) {
                CancelIo(temp_info.overlapped->hEvent);
            }
        }

        if (flag_val & EF_OVERRIDE_IO) continue;


        free_send_info(&temp_info);
        return 0;
    }
    cleanup:

    flag_val = get_event_flag(flag);
    if (flag_val & EF_TERMINATION) {return -1;}

    free_send_info(&temp_info);
    return routine_ret;
}
int send_file_packet(active_file_t *file, const unsigned char *const pk, socket_ll* sockets, EFLAG *flag) {
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    packet_t packet;
    size_t read_ret;
    int ret;

    if (!file) {
        fprintf(stderr, "send_file_packet(): wrong parameters\n");
        return INDIGO_ERROR_INVALID_PARAM;
    }
    if (!(file->fd)) {
        return INDIGO_SUCCESS;
    }
    if (file->counter == 0) {
        randombytes_buf(file->nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    }
    memcpy(nonce,file->nonce,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ret = nonce_increment(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, file->counter);
    if (ret) {
        fprintf(stderr, "nonce_increment() failed in send_file_packet()\n");
        return ret;
    }

    build_packet(&packet, MSG_FILE_CHUNK,pk, nonce, NULL);
    read_ret = fread(packet.data, PAC_DATA_BYTES_USABLE, 1, file->fd);
    if (read_ret != 0) {
        ret = feof(file->fd);
        if (ret != 0) {
            fprintf(stderr, "fread() failed in send_file_packet()\n");
            return -1;
        }
        fclose(file->fd);
        file->fd = NULL;
    }

    ret = encrypt_packet(&packet, file->tk, nonce);
    if (ret) {
        fprintf(stderr,"encrypt_packet() failed in send_file_packet()\n");
        return ret;
    }
    ret = send_packet(file->port, file->ip, sockets, &packet, flag);
    if (ret != 0) {
        fprintf(stderr, "send_packet() failed in send_file_packet()\n");
        return ret;
    }

    return INDIGO_SUCCESS;
}

/////////////////////////////////////////////////////////////
///                                                       ///
///                  IO_HELPER_FUNCTIONS                  ///
///                                                       ///
/////////////////////////////////////////////////////////////

void build_packet(packet_t * restrict packet, const unsigned pac_type, const unsigned char id[crypto_sign_PUBLICKEYBYTES], const unsigned
                  char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], const void * restrict data) {

    sodium_memzero(packet, sizeof(packet_t));

    switch (pac_type) {
        case MSG_INIT_PACKET:
        case MSG_SIGNING_REQUEST:
        case MSG_SIGNING_RESPONSE:
        case MSG_ERR:
            packet->magic_number = MAGIC_NUMBER_1;
            break;
        case MSG_FILE_SENDING_REQUEST:
        case MSG_FILE_SENDING_RESPONSE:
        case MSG_FILE_CHUNK:
        case MSG_RESEND:
        case MSG_STOP_FILE_TRANSMISSION:
        case MSG_PAUSE_FILE_TRANSMISSION:
        case MSG_CONTINUE_FILE_TRANSMISSION:
            packet->magic_number = MAGIC_NUMBER_2;
            break;
        default:
        packet->magic_number = MAGIC_NUMBER_1;
        break;
    }

    memcpy(packet->id, id, crypto_sign_PUBLICKEYBYTES);
    if (nonce) memcpy(packet->nonce, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    packet->pac_type = pac_type;
    packet->pac_version = PAC_VERSION;

    if (data) memcpy(packet->data, data, PAC_DATA_BYTES);

}

int create_handle_array_from_send_info(const SEND_INFO *info, const size_t infolen, HANDLE **handles, size_t *hCount) {
    void *temp;
    if (info == NULL || handles == NULL || hCount == NULL) return 1;

    temp = malloc(infolen * sizeof(HANDLE));
    if (temp == NULL) {
        perror("Failed to allocate memory for send info");
        return 1;
    }
    *handles = temp;
    *hCount = infolen;

    for (size_t i = 0; i < infolen; i++) {
        (*handles)[i] = info[i].overlapped->hEvent;
    }

    return 0;
}

void free_send_info(const SEND_INFO *info) {
    if (info == NULL) return;

    free(info->dest);
    free(info->bytes);
    if (info->buf != NULL) {
        free(info->buf->buf);
        free(info->buf);
    }
    if (info->overlapped != NULL) {
        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
    }
}

int allocate_recv_info(RECV_INFO **info, mempool_t* mempool) {
    void *temp;
    RECV_INFO *tmp_rcv;

    if (info == NULL) return 1;

    tmp_rcv = (RECV_INFO *)malloc(sizeof(RECV_INFO));
    if (tmp_rcv == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        *info = NULL;
        return 1;
    }

    temp = malloc(sizeof (struct sockaddr));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->source = temp;

    temp = malloc(sizeof (int));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->fromLen = temp;
    *(tmp_rcv->fromLen) = sizeof(struct sockaddr);


    temp = malloc(sizeof (WSABUF));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(tmp_rcv->fromLen);
        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->buf = temp;
    tmp_rcv->buf->buf = NULL;

    temp = mempool->alloc(mempool);
    if (temp == NULL) {
        fprintf(stderr, "mempool alloc failed in allocate_recv_info()\n");

        free(tmp_rcv->buf);
        free(tmp_rcv->fromLen);
        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    (*info)->buf->buf = temp;
    (*info)->buf->len = sizeof(packet_t) + sizeof(packet_info_t);

    temp = malloc(sizeof (OVERLAPPED));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        mempool->free(mempool,(*info)->buf->buf);
        free(tmp_rcv->buf);
        free(tmp_rcv->fromLen);
        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->overlapped = temp;
    tmp_rcv->overlapped->hEvent = WSACreateEvent();
    if (tmp_rcv->overlapped->hEvent == WSA_INVALID_EVENT) {
        fprintf(stderr, "WSACreateEvent failed in allocate_recv_info()\n");

        free(tmp_rcv->overlapped);
        mempool->free(mempool,tmp_rcv->buf->buf);
        free(tmp_rcv->buf);
        free(tmp_rcv->fromLen);
        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }

    temp = malloc(sizeof (DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        WSACloseEvent(tmp_rcv->overlapped->hEvent);
        free(tmp_rcv->overlapped);
        mempool->free(mempool,tmp_rcv->buf->buf);
        free(tmp_rcv->buf);
        free(tmp_rcv->fromLen);
        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->flags = temp;

    temp = malloc(sizeof (DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(tmp_rcv->flags);
        WSACloseEvent((*info)->overlapped->hEvent);
        free(tmp_rcv->overlapped);
        mempool->free(mempool,tmp_rcv->buf->buf);
        free(tmp_rcv->buf);
        free(tmp_rcv->fromLen);
        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->bytes_recv = temp;

    tmp_rcv->socket = INVALID_SOCKET;

    *info = tmp_rcv;

    return 0;
}

int allocate_recv_info_fields(RECV_INFO *info, mempool_t* mempool) {
    void *temp;

    if (info == NULL) {return 1;}

    temp = malloc(sizeof (struct sockaddr));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        return 1;
    }
    info->source = temp;

    temp = malloc(sizeof (int));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        free(info->source);
        return 1;
    }
    info->fromLen = temp;
    *(info->fromLen) = sizeof(struct sockaddr);

    temp = malloc(sizeof (WSABUF));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->fromLen);
        free(info->source);
        return 1;
    }
    info->buf = temp;
    info->buf->buf = NULL;

    temp = mempool->alloc(mempool);
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->buf->buf = temp;
    info->buf->len = sizeof(packet_t) + sizeof(packet_info_t);

    temp = malloc(sizeof (OVERLAPPED));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        mempool->free(mempool,info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->overlapped = temp;

    info->overlapped->hEvent = WSACreateEvent();
    if (info->overlapped->hEvent == WSA_INVALID_EVENT) {
        fprintf(stderr, "WSACreateEvent failed in allocate_recv_info()\n");

        free(info->overlapped);
        mempool->free(mempool,info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);
        return 1;
    }

    temp = malloc(sizeof (DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
        mempool->free(mempool,info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);
        return 1;
    }
    info->flags = temp;

    temp = malloc(sizeof (DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->flags);
        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
        mempool->free(mempool,info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->bytes_recv = temp;

    info->socket = INVALID_SOCKET;

    return 0;
}

void free_recv_info(const RECV_INFO *info, mempool_t* mempool) {
    if (info == NULL) {return;}


    if (info->buf) {
        mempool->free(mempool,info->buf->buf);
        free(info->buf);
    }
    if (info->overlapped) {
        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
    }

    free(info->fromLen);
    free(info->source);
    free(info->bytes_recv);
    free(info->flags);
}

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////
//todo: implement control signals for the packets (stop, pause, continue, resend)
int *send_thread(SEND_ARGS *args) {
    uint32_t flag_val;
    struct timespec deadline_ts;
    struct timespec current_ts;
    QNODE *node;
    active_file_t *active_files = NULL; //todo: use an array of pointers to the nodes, the empty nodes do a linked list of empty nodes,
    BUF *fid_array;                     //todo for each active file assign a fid (serial number) (the fid is the index of the array)
    active_file_t *tmp_af;
    active_file_t *curr_af;
    int *process_return = NULL;
    int ret;

    //allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;
    fid_array = new_buffer(sizeof(void *), 1<<7);
    if (!fid_array) {
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

        if (flag_val & EF_OVERRIDE_IO) {
            wait_on_flag_condition(args->flag, EF_OVERRIDE_IO, OFF);
        }

        else if (flag_val & EF_SEND_MULTIPLE_PACKETS) {

            reset_single_event(args->flag, EF_SEND_MULTIPLE_PACKETS);

            ret = send_discovery_packets(args->port,args->multicast_addr,args->sockets,args->flag,3,150, args->sign_keys,TODO);
            if (ret > 0) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                free_buffer(fid_array);
                *process_return = ret;
                return process_return;
            }
            //returns -1 when we get an override execution or termination event
            if (ret == -1) {
                flag_val = get_event_flag(args->flag);
                if(flag_val & EF_TERMINATION){
                    free_buffer(fid_array);
                    *process_return = 0;
                    return process_return;
                }
            }
        }
        else if (flag_val & EF_SEND_NEW_FILE) {
            node = queue_pop(args->queue,QOPT_NON_BLOCK);

            if (node == NULL) continue;

            if (node->type == QET_SEND_FILE) {
                if (active_files) {
                    tmp_af = node->data;
                    tmp_af->next = active_files;
                    active_files = tmp_af;
                }
                else {
                    active_files = node->data;
                }
            }
            destroy_qnode(node);
        }//we don't care about other events, if they are there we shouldn't get them anyway


        //////////////////////////////////////////////////
        ///  phase 2: send file and discovery packets  ///
        //////////////////////////////////////////////////

        tmp_af = NULL;
        curr_af = active_files;
        while (curr_af) {
            ret = send_file_packet(curr_af,args->sign_keys->public, args->sockets, args->flag);
            if (ret) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                free_buffer(fid_array);
                *process_return = ret;
                return process_return;
            }
            if (!curr_af->fd) {
                if (tmp_af) {
                    tmp_af->next = curr_af->next;
                    free(curr_af);
                    curr_af = tmp_af->next;
                }
                else {
                    active_files = curr_af->next;
                    free(curr_af);
                    curr_af = active_files;
                }
                continue;
            }

            //check if we need to send discovery packets
            clock_gettime(CLOCK_REALTIME, &current_ts);
            if (deadline_ts.tv_sec <= current_ts.tv_sec && deadline_ts.tv_nsec <= current_ts.tv_nsec) break;

            tmp_af = curr_af;
            curr_af = curr_af->next;
        }
        //supply the username, if it will be file tied remove
        ret = send_discovery_packets(args->port,args->multicast_addr,args->sockets,args->flag,1,0, args->sign_keys, TODO);
        if (ret > 0) {
            set_event_flag(args->flag, EF_TERMINATION);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            free_buffer(fid_array);
            *process_return = ret;
            return process_return;
        }
        //returns -1 when we get an override execution or termination event
        if (ret == -1) {
            flag_val = get_event_flag(args->flag);
            if(flag_val & EF_TERMINATION){
                free_buffer(fid_array);
                *process_return = 0;
                return process_return;
            }
        }
        //set next deadline
        clock_gettime(CLOCK_REALTIME, &deadline_ts);
        deadline_ts.tv_sec += DISCOVERY_SEND_PERIOD_SEC;


        /////////////////////////////////////////////////
        ///  phase 3: wait and check for termination  ///
        /////////////////////////////////////////////////

        pthread_mutex_lock(&(args->flag->mutex));
        if (args->flag->event_flag & EF_TERMINATION) {
            free_event_flag(args->flag);
            free(args);
            *process_return = 0;
            break;
        }
        ret = 0;
        //while there are no more files to send, and we didn't time out and the termination or new file flag is risen
        while (!active_files && ret == 0 && !(args->flag->event_flag & (EF_TERMINATION | EF_SEND_NEW_FILE))) {
            ret = pthread_cond_timedwait(&(args->flag->cond), &(args->flag->mutex), &deadline_ts);

            if ((ret != ETIMEDOUT) && (ret != 0)) {
                fprintf(stderr, "pthread_cond_timedwait() failed in device_discovery_sending\n");
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                pthread_mutex_unlock(&(args->flag->mutex));
                free_buffer(fid_array);
                *process_return = INDIGO_ERROR_INVALID_STATE;
                return process_return;
            }
            if (ret == 0) {
                if (args->flag->event_flag & EF_TERMINATION) {
                    pthread_mutex_unlock(&(args->flag->mutex));
                    free_buffer(fid_array);
                    *process_return = 0;
                    return process_return;
                }
            }
        }
        pthread_mutex_unlock(&(args->flag->mutex));

    }
    free_buffer(fid_array);
    return process_return;
}

int *recv_thread(RECV_ARGS *args) {
    //todo we need a hash table to hold the expected packets
    RECV_ARRAY info = {0};
    RECV_INFO *recv_info = NULL;

    HANDLE *handles = NULL;
    size_t hCount;

    udp_packet_header_t pack_h;

    packet_info_t *packet_info = NULL;

    uint32_t flag_val;
    DWORD wait_ret;
    int ret;

    int *process_return = NULL;

    //allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;


    //register all the sockets for receiving
    ret = register_multiple_receivers(args->sockets,&info,args->mempool, args->flag);
    if (ret > 0) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = ret;
        return process_return;
    }
    if (ret == -1) {
        flag_val = get_event_flag(args->flag);
        if(flag_val & EF_TERMINATION){
            *process_return = 0;
            return process_return;
        }
    }

    //create the handles array to wait for a packet
    ret = create_handle_array_from_recv_info(&info,&handles,&hCount);
    if (ret) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        free_recv_array(&info, args->mempool);
        *process_return = ret;
        return process_return;
    }

    handles[0] = args->termination_handle;
    handles[1] = args->wake_handle;

    while (!termination_is_on(args->flag)) {
        ///////////////////////////////////
        ///  phase 1: check for events  ///
        ///////////////////////////////////

        flag_val = get_event_flag(args->flag);

        if (flag_val & EF_OVERRIDE_IO) {
            free(handles);
            free_recv_array(&info, args->mempool);
            info.array = NULL;
            info.size = 0;
            hCount = 0;

            wait_on_flag_condition(args->flag, EF_OVERRIDE_IO, OFF);

            ret = register_multiple_receivers(args->sockets,&info, args->mempool, args->flag);
            if (ret > 0) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                *process_return = ret;
                return process_return;
            }

            if (ret == -1) {
                flag_val = get_event_flag(args->flag);
                if(flag_val & EF_TERMINATION){
                    *process_return = 0;
                    return process_return;
                }
            }

            //create the handles array to wait for a packet
            ret = create_handle_array_from_recv_info(&info,&handles,&hCount);
            if (ret) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                free_recv_array(&info, args->mempool);
                *process_return = ret;
                return process_return;
            }

            handles[0] = args->termination_handle;
            handles[1] = args->wake_handle;
        }
        else if (flag_val & EF_TERMINATION) {
            free(handles);
            free_recv_array(&info, args->mempool);
            *process_return = 0;
            return process_return;
        }

        ////////////////////////////////////
        ///  phase 2: wait for a packet  ///
        ////////////////////////////////////

        //todo limit the maximum handles to WSA_MAXIMUM_WAIT_EVENTS (64)
        //todo set a long timeout, to prevent deadlock (idk windows says something like that)

        wait_ret = WSAWaitForMultipleEvents(hCount, handles,FALSE,WSA_INFINITE,FALSE);

        /////////////////////////////////////
        ///  phase 3: process the packet  ///
        /////////////////////////////////////

        if (wait_ret == WSA_WAIT_FAILED) {
            fprintf(stderr, "WSAWaitForMultipleEvents() failed in recv_thread: %d\n", WSAGetLastError());
            set_event_flag(args->flag, EF_TERMINATION);
            set_event_flag(args->wake, EF_WAKE_MANAGER);

            free(handles);
            free_recv_array(&info, args->mempool);

            *process_return = 1;
            return process_return;
        }

        wait_ret -= WSA_WAIT_EVENT_0;

        //the termination handle is signaled
        if (wait_ret == 0) {
            free(handles);
            free_recv_array(&info, args->mempool);

            *process_return = 0;
            return process_return;
        }

        //the wake handle is signaled
        if (wait_ret == 1) {
            WSAResetEvent(handles[1]);
            continue;
        } // we got a wake event so we continue

//check the handles one by one
        for (size_t i = wait_ret; i < hCount; i++) {
            //check is the event is signaled
            wait_ret = WaitForSingleObject(handles[i],0);

            if (wait_ret == WAIT_FAILED) {
                printf("WaitForSingleObject() failed in recv_thread: %d\n", WSAGetLastError());
                fflush(stdout);
                free(handles);
                free_recv_array(&info, args->mempool);

                *process_return = 0;
                return process_return;
            }

            if (wait_ret == WAIT_OBJECT_0){
                //we received on that socket
                recv_info = (info.array) + i - 2;

                //check the packet we received

                if ((*(recv_info->bytes_recv) > sizeof(packet_t)) || (*(recv_info->bytes_recv) < PAC_MIN_BYTES)){
                    WSAResetEvent(handles[i]);
                    if (register_single_receiver(recv_info->socket,&recv_info, args->mempool)) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free_recv_array(&info, args->mempool);
                        free(handles);
                        return process_return;
                    }
                    continue;
                }

                //everything we need to know is in the first 6 bytes, the rest is redundant
                memcpy(&pack_h,recv_info->buf->buf,sizeof(udp_packet_header_t));

                //check the magic number (not an absolut way to check if a packet is for us but will prolly work)
                if (pack_h.magic_number != MAGIC_NUMBER_1 || pack_h.magic_number != MAGIC_NUMBER_2) {

                    WSAResetEvent(handles[i]);
                    if (register_single_receiver(recv_info->socket,&recv_info, args->mempool)) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free_recv_array(&info, args->mempool);
                        free(handles);
                        return process_return;
                    }
                    continue;
                }

                //we need to push the pointer to the received data (recv_info->buf->buf)

                //push the packet to be processed
                //the buffer has enough space for the packet and metadata (packet_info)
                //(its like a struct, but it's not),
                //I've agreed that we don't need a struct, and I will mess up like real fag

                //here we put the packet info at the end of the buffer that we received (there is enough space)

                packet_info = (packet_info_t *)(recv_info->buf->buf + sizeof(packet_t));
                packet_info->address = *(struct sockaddr_in *)(recv_info->source);
                packet_info->socket = recv_info->socket;



                if (queue_push(args->queue,recv_info->buf->buf,QET_NEW_PACKET)) {
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    free_recv_array(&info, args->mempool);
                    free(handles);
                    return process_return;
                }
                set_event_flag(args->flag, EF_NEW_PACKET);
                set_event_flag(args->wake, EF_WAKE_MANAGER);

                //reset and re-receive
                WSAResetEvent(handles[i]);

                //we need to allocate a new buffer for receiving from the pool
                recv_info->buf->buf = args->mempool->alloc(args->mempool);
                if (recv_info->buf->buf == NULL) {
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    free_recv_array(&info, args->mempool);
                    free(handles);
                    return process_return;
                }

                if (register_single_receiver(recv_info->socket,&recv_info, args->mempool)) {
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_WINLIB_ERROR;
                    free_recv_array(&info, args->mempool);
                    free(handles);
                    return process_return;
                }
            }
        }
    }
    free(handles);
    free_recv_array(&info, args->mempool);
    *process_return = 0;
    return process_return;
}

/////////////////////////////////////////////////////////////////
///                                                           ///
///                  THREAD_FUNCTION_HELPERS                  ///
///                                                           ///
/////////////////////////////////////////////////////////////////

int create_handle_array_from_recv_info(const RECV_ARRAY *info, HANDLE **handles, size_t *hCount) {
    if (info == NULL || handles == NULL || hCount == NULL) return 1;

    RECV_INFO *recv = info->array;
    void *temp = malloc(sizeof(HANDLE) * ((info->size) + 2));//we allocate 2 more, 1 for the termination handle
    if (temp == NULL) return 1;                                 //and one for the wake handle

    *handles = temp;
    *hCount = (info->size) + 2;

    for (int i = 0; i < info->size; i++) {
        (*handles)[2 + i] = recv[i].overlapped->hEvent;
    }

    return 0;
}

void free_recv_array(const RECV_ARRAY *info, mempool_t* mempool) {
    for (int i = 0; i < info->size; i++) {
        free_recv_info(&(info->array[i]), mempool);
    }
    free(info->array);
}
