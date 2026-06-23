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

#include <errno.h>
#include <glib-2.0/glib.h>
#include <indigo_core/net_io.h>
#include <indigo_errors.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "Queue.h"
#include "crypto_utils.h"
#include <indigo_types.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "event_flags.h"
#include "lht.h"
#include "mempool.h"
#include "net_monitor.h"

//////////////////////////////////////////////////////
///                                                ///
///                  IO_FUNCTIONS                  ///
///                                                ///
//////////////////////////////////////////////////////

// todo: OVERRIDE_IO is not handled correctly check implementation
#ifdef _WIN32
int send_discovery_packets(const int port, const uint32_t multicast_addr, socket_ll *sockets, EFLAG *flag,
                           const uint32_t pCount, const int32_t msec, signing_key_pair_t *sign_key_pair,
                           wchar_t username[MAX_USERNAME_LEN]) {

    uint8_t restart = 0;
    // temporary variables for memory allocation
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
    // TODO: make this utf8 compatible

    memcpy(username, packet_data.username, MAX_USERNAME_LEN * sizeof(wchar_t));
    wcsncpy(username, username, MAX_USERNAME_LEN);

    while (1) {
        restart = 0;
        pthread_mutex_lock(&sockets->mutex);
        for (socket_node *sock = sockets->head; sock != NULL; sock = sock->next) {
            // for every socket we send we allocate the fields of SEND_INFO (they can't be in the stack)
            temp = calloc(1, sizeof(struct sockaddr_in));
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

            // we resize the sInfo array to hold one more send info
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
            memset(&temp_info, 0, sizeof(SEND_INFO)); // so that we dont double free

            flag_val = get_event_flag(flag);
            if (flag_val & EF_OVERRIDE_IO) {
                // since there is OVERRIDE_IO the sockets we got are not valid (they are being currently updated)
                // free the allocated resources and exit the loop
                free_send_info(&temp_info);
                for (size_t i = 0; i < infolen; i++) {
                    free_send_info(&sInfo[i]);
                }
                free(handles);
                wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
                restart = 1;
                break;
            }
            if (flag_val & EF_TERMINATION)
                goto cleanup;

            curr_time = time(NULL);
            // todo this is wrong because we sign the whole data and not just the timestamp
            crypto_sign((unsigned char *)&packet_data.timestamp, NULL, (unsigned char *)&curr_time, sizeof(time_t),
                        sign_key_pair->secret);

            ret_val = WSASendTo(sock->sock, sInfo[infolen - 1].buf, 1, sInfo[infolen - 1].bytes, MSG_DONTROUTE,
                                (struct sockaddr *)(sInfo[infolen - 1].dest), sizeof(struct sockaddr),
                                sInfo[infolen - 1].overlapped, NULL);

            if (ret_val == SOCKET_ERROR) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                    pthread_mutex_unlock(&sockets->mutex);
                    routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                    goto cleanup;
                }
            }
        }
        pthread_mutex_unlock(&sockets->mutex);

        if (restart)
            continue;

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (msec - temp_math) / 1000;
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
        if (flag_val & EF_TERMINATION)
            goto cleanup;

        pthread_mutex_lock(&flag->mutex);
        pthread_cond_timedwait(&flag->cond, &flag->mutex, &ts);

        if (flag->event_flag & EF_TERMINATION)
            goto cleanup;
        if (flag->event_flag & EF_OVERRIDE_IO) {
            free_send_info(&temp_info);
            for (size_t i = 0; i < infolen; i++) {
                free_send_info(&sInfo[i]);
            }
            wait_on_flag_condition(flag, EF_OVERRIDE_IO, OFF);
            continue;
        }

        pthread_mutex_unlock(&flag->mutex);

        // create the handle array to use to check if the io has finished
        if (create_handle_array_from_send_info(sInfo, infolen, &handles, &hCount)) {
            fprintf(stderr, "create_handle_array_from_send_info() failed in send_discovery_packets()\n");
            routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
            goto cleanup;
        }
        // check if the io is finished
        wait_ret = WSAWaitForMultipleEvents(hCount, handles, TRUE, 100, FALSE);
        if (wait_ret == WSA_WAIT_FAILED) {
            fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
            routine_ret = INDIGO_ERROR_WINLIB_ERROR;
            goto cleanup;
        }
        if (wait_ret == WSA_WAIT_TIMEOUT) {
            for (size_t i = 0; i < hCount; i++) {
                wait_ret = WaitForSingleObject(handles[i], 0);
                if (wait_ret == WAIT_OBJECT_0)
                    continue;

                if (wait_ret == WAIT_FAILED) {
                    fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n",
                            WSAGetLastError());
                    goto cleanup;
                }

                if (wait_ret == WAIT_TIMEOUT) {
                    CancelIo(handles[i]);
                }
            }
        }

        if (sInfo == NULL)
            goto cleanup;

        // send the rest of the packets based on the previous SEND_INFO allocations
        for (size_t i = 0; i < pCount - 1; i++) {
            for (size_t j = 0; j < infolen; j++) {
                WSAResetEvent(handles[j]);

                ret_val = WSASendTo(sInfo[j].socket, sInfo->buf, 1, sInfo->bytes, MSG_DONTROUTE,
                                    (struct sockaddr *)(sInfo->dest), sizeof(struct sockaddr), sInfo->overlapped, NULL);

                if (ret_val == SOCKET_ERROR) {
                    if (WSAGetLastError() != WSA_IO_PENDING) {
                        fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                        pthread_mutex_unlock(&sockets->mutex);

                        routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                        goto cleanup;
                    }
                }
            }

            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (msec - temp_math) / 1000;
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
            if (flag_val & EF_TERMINATION)
                goto cleanup;

            pthread_mutex_lock(&flag->mutex);
            pthread_cond_timedwait(&flag->cond, &flag->mutex, &ts);

            if (flag->event_flag & EF_TERMINATION)
                goto cleanup;
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

            if (create_handle_array_from_send_info(sInfo, infolen, &handles, &hCount)) {
                fprintf(stderr, "create_handle_array_from_send_info() failed in send_discovery_packets()\n");
                routine_ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                goto cleanup;
            }

            wait_ret = WSAWaitForMultipleEvents(hCount, handles, TRUE, 100, FALSE);
            if (wait_ret == WSA_WAIT_FAILED) {
                fprintf(stderr, "WaitForMultipleObjects() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                goto cleanup;
            }
            if (wait_ret == WSA_WAIT_TIMEOUT) {
                for (size_t k = 0; k < hCount; k++) {
                    wait_ret = WaitForSingleObject(handles[i], 0);
                    if (wait_ret == WAIT_OBJECT_0)
                        continue;

                    if (wait_ret == WAIT_FAILED) {
                        fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n",
                                WSAGetLastError());
                        routine_ret = INDIGO_ERROR_WINLIB_ERROR;
                        goto cleanup;
                    }

                    if (wait_ret == WAIT_TIMEOUT) {
                        CancelIo(handles[k]);
                    }
                }
            }
        }
        if (flag_val & EF_OVERRIDE_IO)
            continue;

        free_send_info(&temp_info); // temporary
        for (size_t i = 0; i < infolen; i++) {
            free_send_info(&sInfo[i]);
        }
        free(handles);
        return 0;
    }
cleanup:

    flag_val = get_event_flag(flag);
    if (flag_val & EF_TERMINATION)
        return -1;

    free_send_info(&temp_info);
    for (size_t i = 0; i < infolen; i++) {
        free_send_info(&sInfo[i]);
    }
    free(handles);
    return routine_ret;
}
int register_single_receiver(SOCKET sock, RECV_INFO **info, mempool_t *mempool) {
    RECV_INFO *temp_info;

    int recv_ret;

    if (!info || !mempool) {
        fprintf(stderr, "register_single_receiver called with info or mempool NULL\n");
        return -1;
    }

    // if we are not provided an allocated RECV_INFO (most likely on first use)
    if (*info == NULL) {

        if (allocate_recv_info(&temp_info, mempool)) {
            fprintf(stderr, "allocate_recv_info() failed in send_discovery_packets()\n");
            return 1;
        }

        temp_info->socket = sock;
        *(temp_info->flags) = 0;

        recv_ret = WSARecvFrom(sock, temp_info->buf, 1, temp_info->bytes_recv, temp_info->flags, temp_info->source,
                               temp_info->fromLen, temp_info->overlapped, NULL);

        if (recv_ret == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr, "WSARecvFrom() failed in register_single_discovery_receiver(): %d\n",
                        WSAGetLastError());
                free_recv_info(temp_info, mempool);
                free(temp_info);
                return 1;
            }
        }
        *info = temp_info;
    } else {
        // if we are provided an allocated RECV_INFO (most likely from previous use)
        recv_ret = WSARecvFrom(sock, (*info)->buf, 1, (*info)->bytes_recv, (*info)->flags, (*info)->source,
                               (*info)->fromLen, (*info)->overlapped, NULL);

        if (recv_ret == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr, "WSARecvFrom() failed in register_single_discovery_receiver(): %d\n",
                        WSAGetLastError());
                return 1;
            }
        }
    }

    return 0;
}

int register_multiple_receivers(socket_ll *sockets, RECV_ARRAY *info, mempool_t *mempool, EFLAG *flag) {
    void *temp = NULL;
    RECV_INFO *tempinf = NULL;

    uint32_t flag_val = 0;

    int recv_ret;
    // in case we get an override flag we restart
    while (1) {
        flag_val = 0;

        info->array = NULL;
        info->size = 0;

        pthread_mutex_lock(&sockets->mutex);
        // for every socket available
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

            recv_ret = WSARecvFrom(sock->sock, tempinf->buf, 1, tempinf->bytes_recv, tempinf->flags, tempinf->source,
                                   tempinf->fromLen, tempinf->overlapped, NULL);

            if (recv_ret == SOCKET_ERROR) {
                if (WSAGetLastError() != WSA_IO_PENDING) {
                    fprintf(stderr, "WSARecvFrom() failed in register_multiple_discovery_receivers(): %d\n",
                            WSAGetLastError());
                    pthread_mutex_unlock(&sockets->mutex);
                    return 1;
                }
            }
        }
        pthread_mutex_unlock(&sockets->mutex);
        if (flag_val & EF_OVERRIDE_IO) {
            continue;
        }
        return 0;
    }
}
int send_packet(const int port, const uint32_t addr, socket_ll *sockets, const packet_t *const packet, EFLAG *flag) {
    SEND_INFO temp_info;
    SOCKET sock;
    void *temp;
    int ret_val;
    DWORD wait_ret;
    uint32_t flag_val = 0;
    int routine_ret = 0;

    while (1) {
        temp = calloc(1, sizeof(struct sockaddr_in));
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
        if (flag_val & EF_TERMINATION)
            goto cleanup;

        pthread_mutex_lock(&sockets->mutex);
        sock = ip_to_socket(addr, sockets);

        ret_val = WSASendTo(sock, temp_info.buf, 1, temp_info.bytes, MSG_DONTROUTE, (struct sockaddr *)(temp_info.dest),
                            sizeof(struct sockaddr), temp_info.overlapped, NULL);
        pthread_mutex_unlock(&sockets->mutex);

        if (ret_val == SOCKET_ERROR) {
            ret_val = WSAGetLastError();
            if (ret_val != WSA_IO_PENDING) {
                fprintf(stderr, "WSASendTo() failed in send_discovery_packets(): %d\n", ret_val);
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
            routine_ret = INDIGO_ERROR_WINLIB_ERROR; // todo: change to something that can be handled, i really dont
                                                     // know what it should be
            goto cleanup;
        }
        if (wait_ret == WAIT_TIMEOUT) {
            wait_ret = WaitForSingleObject(temp_info.overlapped->hEvent, 150);
            // if (wait_ret == WAIT_OBJECT_0) continue; //todo: check for correctness, why should this line exist

            if (wait_ret == WAIT_FAILED) {
                fprintf(stderr, "WaitForSingleObject() failed in send_discovery_packets(): %d\n", WSAGetLastError());
                goto cleanup;
            }

            if (wait_ret == WAIT_TIMEOUT) {
                CancelIo(temp_info.overlapped->hEvent);
            }
        }

        if (flag_val & EF_OVERRIDE_IO)
            continue;

        free_send_info(&temp_info);
        return 0;
    }
cleanup:

    flag_val = get_event_flag(flag);
    if (flag_val & EF_TERMINATION) {
        return -1;
    }

    free_send_info(&temp_info);
    return routine_ret;
}
#else
int register_single_event(int epoll_fd, int fd, struct epoll_event event) {
    event.data.fd = fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1) {
        return INDIGO_ERROR;
    }
    return INDIGO_SUCCESS;
}
int register_multiple_receivers(int epoll_fd, socket_ll *sockets, size_t *event_count) {
    struct epoll_event *recv_events;
    size_t count;

    if (!event_count || !event_count)
        return INDIGO_ERROR_INVALID_PARAM;

    pthread_mutex_lock(&(sockets->mutex));

    // count how many sockets we have
    for (socket_node *sn = sockets->head; sn != NULL; sn = sn->next)
        ++count;
    recv_events = calloc(count, sizeof(struct epoll_event));
    if (!recv_events) {
        pthread_mutex_unlock(&(sockets->mutex));
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    *event_count = count;

    // count is now a counter
    // register the sockets one by one
    count = 0;
    for (socket_node *sn = sockets->head; sn != NULL; sn = sn->next) {
        recv_events[count].events = EPOLLIN;
        recv_events[count].data.fd = sn->sock;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sn->sock, &(recv_events[count])) == -1) {
            pthread_mutex_unlock(&(sockets->mutex));
            free(recv_events);
            return INDIGO_ERROR;
        }
        ++count;
    }

    pthread_mutex_unlock(&(sockets->mutex));
    free(recv_events);
    return INDIGO_SUCCESS;
}
int send_discovery_packets(const int port, const uint32_t multicast_addr, socket_ll *sockets, EFLAG *flag,
                           const uint32_t pCount, const int32_t msec, signing_key_pair_t *sign_key_pair,
                           wchar_t username[MAX_USERNAME_LEN]) {
    int ret;
    time_t curr_time;
    packet_t packet;
    struct sockaddr_in s_addr = {0};
    init_packet_data_t packet_data;

    s_addr.sin_addr.s_addr = multicast_addr;
    s_addr.sin_port = PORT;
    s_addr.sin_family = AF_INET;

    build_packet(&packet, MSG_INIT_PACKET, sign_key_pair->public, NULL, NULL);
    strcpy((char *)packet_data.username, (char *)username);
    pthread_mutex_lock(&(sockets->mutex));
    for (uint32_t i = 0; i < pCount; i++) {
        curr_time = time(NULL);
        crypto_sign((unsigned char *)&packet_data.timestamp, NULL, (unsigned char *)&curr_time, sizeof(time_t),
                    sign_key_pair->secret);
        memcpy(&packet.data, &packet_data, sizeof(init_packet_data_t));
        for (socket_node *s = sockets->head; s != NULL; s = s->next) {
            ret = sendto(s->sock, &packet, sizeof(packet_t), 0, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in));
            if (ret == -1) {
                // TODO: handle errors
            }
        }
        g_usleep(1000 * msec);
    }
    pthread_mutex_unlock(&(sockets->mutex));

    return 0;
}

int send_packet(const int port, const uint32_t addr, socket_ll *sockets, const packet_t *const packet, EFLAG *flag) {

    int ret = 0;
    int sock;
    struct sockaddr_in s_addr = {0};

    if (!sockets || !packet)
        return INDIGO_ERROR_INVALID_PARAM;

    s_addr.sin_addr.s_addr = addr;
    s_addr.sin_port = PORT;
    s_addr.sin_family = AF_INET;

    pthread_mutex_lock(&sockets->mutex);
    sock = ip_to_socket(addr, sockets);

    ret = sendto(sock, packet, sizeof(packet_t), 0, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in));
    pthread_mutex_unlock(&sockets->mutex);
    if (ret == -1) {
        switch (errno) {
            // TODO: handle the errors.
        }
        return 1;
    }
    return 0;
}
#endif
int send_next_file_packet(active_file_t *file, const unsigned char *const pk, socket_ll *sockets, EFLAG *flag) {
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    packet_t packet;
    size_t read_ret;
    int ret;

    if (!file) {
        fprintf(stderr, "send_next_file_packet(): wrong parameters\n");
        return INDIGO_ERROR_INVALID_PARAM;
    }
    if (!(file->fd)) {
        return INDIGO_SUCCESS;
    }
    if (file->counter == 0) {
        randombytes_buf(file->nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    }
    memcpy(nonce, file->nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ret = nonce_increment(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, file->counter);
    if (ret) {
        fprintf(stderr, "nonce_increment() failed in send_next_file_packet()\n");
        return ret;
    }

    build_packet(&packet, MSG_FILE_CHUNK, pk, nonce, NULL);
    read_ret = fread(packet.data, PAC_DATA_BYTES_USABLE, 1, file->fd);
    if (read_ret != 0) {
        ret = feof(file->fd);
        if (ret != 0) {
            fprintf(stderr, "fread() failed in send_next_file_packet()\n");
            return -1;
        }
        fclose(file->fd);
        file->fd = NULL;
    }

    ret = encrypt_packet(&packet, file->tk, nonce);
    if (ret) {
        fprintf(stderr, "encrypt_packet() failed in send_next_file_packet()\n");
        return ret;
    }
    ret = send_packet(file->port, file->ip, sockets, &packet, flag);
    if (ret != 0) {
        fprintf(stderr, "send_packet() failed in send_next_file_packet()\n");
        return ret;
    }
    file->counter++;

    return INDIGO_SUCCESS;
}

int send_file_packet(active_file_t *file, uint64_t counter, const unsigned char *const pk, socket_ll *sockets,
                     EFLAG *flag) {
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    packet_t packet;
    size_t read_ret;
    int ret;

    if (!file) {
        fprintf(stderr, "send_next_file_packet(): wrong parameters\n");
        return INDIGO_ERROR_INVALID_PARAM;
    }
    if (!(file->fd)) {
        return INDIGO_SUCCESS;
    }
    if (file->counter == 0) {
        randombytes_buf(file->nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    }
    memcpy(nonce, file->nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ret = nonce_increment(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, counter);
    if (ret) {
        fprintf(stderr, "nonce_increment() failed in send_next_file_packet()\n");
        return ret;
    }

    build_packet(&packet, MSG_FILE_CHUNK, pk, nonce, NULL);
    read_ret = fread(packet.data, PAC_DATA_BYTES_USABLE, 1, file->fd);
    if (read_ret != 0) {
        ret = feof(file->fd);
        if (ret != 0) {
            fprintf(stderr, "fread() failed in send_next_file_packet()\n");
            return -1;
        }
        fclose(file->fd);
        file->fd = NULL;
    }

    ret = encrypt_packet(&packet, file->tk, nonce);
    if (ret) {
        fprintf(stderr, "encrypt_packet() failed in send_next_file_packet()\n");
        return ret;
    }
    ret = send_packet(file->port, file->ip, sockets, &packet, flag);
    if (ret != 0) {
        fprintf(stderr, "send_packet() failed in send_next_file_packet()\n");
        return ret;
    }
    return INDIGO_SUCCESS;
}
/////////////////////////////////////////////////////////////
///                                                       ///
///                  IO_HELPER_FUNCTIONS                  ///
///                                                       ///
/////////////////////////////////////////////////////////////

void build_packet(packet_t *restrict packet, const unsigned pac_type,
                  const unsigned char id[crypto_sign_PUBLICKEYBYTES],
                  const unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], const void *restrict data) {

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
    if (nonce)
        memcpy(packet->nonce, nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    packet->pac_type = pac_type;
    packet->pac_version = PAC_VERSION;

    if (data)
        memcpy(packet->data, data, PAC_DATA_BYTES);
}

#ifdef _WIN32
int create_handle_array_from_send_info(const SEND_INFO *info, const size_t infolen, HANDLE **handles, size_t *hCount) {
    void *temp;
    if (info == NULL || handles == NULL || hCount == NULL)
        return 1;

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
    if (info == NULL)
        return;

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

int allocate_recv_info(RECV_INFO **info, mempool_t *mempool) {
    void *temp;
    RECV_INFO *tmp_rcv;

    if (info == NULL)
        return 1;

    tmp_rcv = (RECV_INFO *)malloc(sizeof(RECV_INFO));
    if (tmp_rcv == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        *info = NULL;
        return 1;
    }

    temp = malloc(sizeof(struct sockaddr));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->source = temp;

    temp = malloc(sizeof(int));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->fromLen = temp;
    *(tmp_rcv->fromLen) = sizeof(struct sockaddr);

    temp = malloc(sizeof(WSABUF));
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

    temp = malloc(sizeof(OVERLAPPED));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        mempool->free(mempool, (*info)->buf->buf);
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
        mempool->free(mempool, tmp_rcv->buf->buf);
        free(tmp_rcv->buf);
        free(tmp_rcv->fromLen);
        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }

    temp = malloc(sizeof(DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        WSACloseEvent(tmp_rcv->overlapped->hEvent);
        free(tmp_rcv->overlapped);
        mempool->free(mempool, tmp_rcv->buf->buf);
        free(tmp_rcv->buf);
        free(tmp_rcv->fromLen);
        free(tmp_rcv->source);
        free(tmp_rcv);

        *info = NULL;
        return 1;
    }
    tmp_rcv->flags = temp;

    temp = malloc(sizeof(DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(tmp_rcv->flags);
        WSACloseEvent((*info)->overlapped->hEvent);
        free(tmp_rcv->overlapped);
        mempool->free(mempool, tmp_rcv->buf->buf);
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

int allocate_recv_info_fields(RECV_INFO *info, mempool_t *mempool) {
    void *temp;

    if (info == NULL) {
        return 1;
    }

    temp = malloc(sizeof(struct sockaddr));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        return 1;
    }
    info->source = temp;

    temp = malloc(sizeof(int));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");
        free(info->source);
        return 1;
    }
    info->fromLen = temp;
    *(info->fromLen) = sizeof(struct sockaddr);

    temp = malloc(sizeof(WSABUF));
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

    temp = malloc(sizeof(OVERLAPPED));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        mempool->free(mempool, info->buf->buf);
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
        mempool->free(mempool, info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);
        return 1;
    }

    temp = malloc(sizeof(DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
        mempool->free(mempool, info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);
        return 1;
    }
    info->flags = temp;

    temp = malloc(sizeof(DWORD));
    if (temp == NULL) {
        fprintf(stderr, "malloc() failed in allocate_recv_info()\n");

        free(info->flags);
        WSACloseEvent(info->overlapped->hEvent);
        free(info->overlapped);
        mempool->free(mempool, info->buf->buf);
        free(info->buf);
        free(info->fromLen);
        free(info->source);

        return 1;
    }
    info->bytes_recv = temp;

    info->socket = INVALID_SOCKET;

    return 0;
}

void free_recv_info(const RECV_INFO *info, mempool_t *mempool) {
    if (info == NULL) {
        return;
    }

    if (info->buf) {
        mempool->free(mempool, info->buf->buf);
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
#endif

//////////////////////////////////////////////////////////
///                                                    ///
///                  THREAD_FUNCTIONS                  ///
///                                                    ///
//////////////////////////////////////////////////////////
// todo: implement control signals for the packets (stop, pause, continue, resend)

#ifdef _WIN32
int *recv_thread(RECV_ARGS *args) {
    // todo we need a hash table to hold the expected packets
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

    // allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;

    // register all the sockets for receiving
    ret = register_multiple_receivers(args->sockets, &info, args->mempool, args->flag);
    if (ret > 0) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = ret;
        return process_return;
    }
    if (ret == -1) {
        flag_val = get_event_flag(args->flag);
        if (flag_val & EF_TERMINATION) {
            *process_return = 0;
            return process_return;
        }
    }

    // create the handles array to wait for a packet
    ret = create_handle_array_from_recv_info(&info, &handles, &hCount);
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

            ret = register_multiple_receivers(args->sockets, &info, args->mempool, args->flag);
            if (ret > 0) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                *process_return = ret;
                return process_return;
            }

            if (ret == -1) {
                flag_val = get_event_flag(args->flag);
                if (flag_val & EF_TERMINATION) {
                    *process_return = 0;
                    return process_return;
                }
            }

            // create the handles array to wait for a packet
            ret = create_handle_array_from_recv_info(&info, &handles, &hCount);
            if (ret) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                free_recv_array(&info, args->mempool);
                *process_return = ret;
                return process_return;
            }

            handles[0] = args->termination_handle;
            handles[1] = args->wake_handle;
        } else if (flag_val & EF_TERMINATION) {
            free(handles);
            free_recv_array(&info, args->mempool);
            *process_return = 0;
            return process_return;
        }

        ////////////////////////////////////
        ///  phase 2: wait for a packet  ///
        ////////////////////////////////////

        // todo limit the maximum handles to WSA_MAXIMUM_WAIT_EVENTS (64)
        // todo set a long timeout, to prevent deadlock (idk windows says something like that)

        wait_ret = WSAWaitForMultipleEvents(hCount, handles, FALSE, WSA_INFINITE, FALSE);

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

        // the termination handle is signaled
        if (wait_ret == 0) {
            free(handles);
            free_recv_array(&info, args->mempool);

            *process_return = 0;
            return process_return;
        }

        // the wake handle is signaled
        if (wait_ret == 1) {
            WSAResetEvent(handles[1]);
            continue;
        } // we got a wake event so we continue

        // check the handles one by one
        for (size_t i = wait_ret; i < hCount; i++) {
            // check is the event is signaled
            wait_ret = WaitForSingleObject(handles[i], 0);

            if (wait_ret == WAIT_FAILED) {
                printf("WaitForSingleObject() failed in recv_thread: %d\n", WSAGetLastError());
                fflush(stdout);
                free(handles);
                free_recv_array(&info, args->mempool);

                *process_return = 0;
                return process_return;
            }

            if (wait_ret == WAIT_OBJECT_0) {
                // we received on that socket
                recv_info = (info.array) + i - 2;

                // check the packet we received

                if ((*(recv_info->bytes_recv) > sizeof(packet_t)) || (*(recv_info->bytes_recv) < PAC_MIN_BYTES)) {
                    WSAResetEvent(handles[i]);
                    if (register_single_receiver(recv_info->socket, &recv_info, args->mempool)) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free_recv_array(&info, args->mempool);
                        free(handles);
                        return process_return;
                    }
                    continue;
                }

                // everything we need to know is in the first 6 bytes, the rest is redundant
                memcpy(&pack_h, recv_info->buf->buf, sizeof(udp_packet_header_t));

                // check the magic number (not an absolut way to check if a packet is for us but will prolly work)
                if (pack_h.magic_number != MAGIC_NUMBER_1 || pack_h.magic_number != MAGIC_NUMBER_2) {

                    WSAResetEvent(handles[i]);
                    if (register_single_receiver(recv_info->socket, &recv_info, args->mempool)) {
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        *process_return = INDIGO_ERROR_WINLIB_ERROR;
                        free_recv_array(&info, args->mempool);
                        free(handles);
                        return process_return;
                    }
                    continue;
                }

                // we need to push the pointer to the received data (recv_info->buf->buf)

                // push the packet to be processed
                // the buffer has enough space for the packet and metadata (packet_info)
                //(its like a struct, but it's not),
                // I've agreed that we don't need a struct, it may not work, but it's ok we can fix it if needed

                // here we put the packet info at the end of the buffer that we received (there is enough space)

                packet_info = (packet_info_t *)(recv_info->buf->buf + sizeof(packet_t));
                packet_info->address = *(struct sockaddr_in *)(recv_info->source);
                packet_info->socket =
                    recv_info->socket; // TODO: we may not need the socket since we have moved to a ip to socket design

                if (queue_push(args->queue, recv_info->buf->buf, QET_NEW_PACKET)) {
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    free_recv_array(&info, args->mempool);
                    free(handles);
                    return process_return;
                }
                set_event_flag(args->flag, EF_NEW_PACKET);
                set_event_flag(args->wake, EF_WAKE_MANAGER);

                // reset and re-receive
                WSAResetEvent(handles[i]);

                // we need to allocate a new buffer for receiving from the pool
                recv_info->buf->buf = args->mempool->alloc(args->mempool);
                if (recv_info->buf->buf == NULL) {
                    set_event_flag(args->flag, EF_TERMINATION);
                    set_event_flag(args->wake, EF_WAKE_MANAGER);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    free_recv_array(&info, args->mempool);
                    free(handles);
                    return process_return;
                }

                if (register_single_receiver(recv_info->socket, &recv_info, args->mempool)) {
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
#else
int *recv_thread(RECV_ARGS *args) {
    // todo we need a hash table to hold the expected packets

    mempool_t *mempool = NULL;
    QUEUE *queue = NULL;

    udp_packet_header_t pack_h;
    int epoll_fd = 0;
    struct epoll_event *recv_events = NULL;
    struct epoll_event tmp_event;
    size_t recv_event_count;

    struct sockaddr_in recv_addr = {0};
    socklen_t recv_addr_len = 0;
    char *recv_buffer = NULL;
    packet_info_t *packet_info = NULL;

    uint32_t event_type = (uint32_t)(-1); // initialized to invalid value
    uint32_t flag_val;
    int ret;
    ssize_t lret;

    int *process_return = NULL;

    // allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;

    mempool = args->mempool;
    queue = args->queue;

    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        *process_return = INDIGO_ERROR_SYS_FAIL;
        return process_return;
    }

    // register all the sockets for receiving
    ret = register_multiple_receivers(epoll_fd, args->sockets, &recv_event_count);
    if (ret != INDIGO_SUCCESS) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = ret;
        return process_return;
    }
    // TODO: i have zero idea why we check the flag bellow, please check it and remove if necessary
    if (ret == -1) {
        flag_val = get_event_flag(args->flag);
        if (flag_val & EF_TERMINATION) {
            *process_return = 0;
            return process_return;
        }
    }
    // we will register 2 more events, the wake event and the termination event
    recv_event_count += 2;
    recv_events = calloc(recv_event_count, sizeof(struct epoll_event));
    if (!recv_events) {
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        return process_return;
    }
    tmp_event.events = EPOLLIN;
    tmp_event.data.fd = args->termination_fd;
    tmp_event.data.u32 = 1;
    register_single_event(epoll_fd, args->termination_fd, tmp_event);
    tmp_event.data.fd = args->wake_fd;
    tmp_event.data.u32 = 2;
    register_single_event(epoll_fd, args->termination_fd, tmp_event);
    memset(&tmp_event, 0, sizeof(struct epoll_event));

    while (!termination_is_on(args->flag)) {
        ///////////////////////////////////
        ///  phase 1: check for events  ///
        ///////////////////////////////////

        flag_val = get_event_flag(args->flag);

        if (flag_val & EF_OVERRIDE_IO) {
            close(epoll_fd);
            epoll_fd = epoll_create1(0);
            if (epoll_fd == -1) {
                *process_return = INDIGO_ERROR_SYS_FAIL;
                return process_return;
            }
            free(recv_events);
            recv_events = NULL;

            // register all the sockets for receiving
            ret = register_multiple_receivers(epoll_fd, args->sockets, &recv_event_count);
            if (ret != INDIGO_SUCCESS) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                *process_return = ret;
                return process_return;
            }
            reset_single_event(args->flag, EF_OVERRIDE_IO);
            // make toom for the termination event
            recv_event_count += 2;
            recv_events = calloc(recv_event_count, sizeof(struct epoll_event));
            if (!recv_events) {
                *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                return process_return;
            }
            tmp_event.events = EPOLLIN;
            tmp_event.data.fd = args->termination_fd;
            tmp_event.data.u32 = 1;
            register_single_event(epoll_fd, args->termination_fd, tmp_event);
            tmp_event.data.fd = args->wake_fd;
            tmp_event.data.u32 = 2;
            register_single_event(epoll_fd, args->termination_fd, tmp_event);
            memset(&tmp_event, 0, sizeof(struct epoll_event));
        } else if (flag_val & EF_TERMINATION) {
            *process_return = 0;
            return process_return;
        }

        ////////////////////////////////////
        ///  phase 2: wait for a packet  ///
        ////////////////////////////////////

        ret = epoll_wait(epoll_fd, recv_events, recv_event_count, 1 << 20);
        if (ret == 0)
            continue;
        else if (ret == -1) {
            free(recv_events);
            *process_return = INDIGO_ERROR;
            return process_return;
        }

        /////////////////////////////////////
        ///  phase 3: process the packet  ///
        /////////////////////////////////////

        // check the epoll events one by one
        for (size_t i = 0; i < recv_event_count; ++i) {
            event_type = recv_events[i].data.u32;
            if (event_type == 1) {
                // we need to terminate
                free(recv_events);
                *process_return = INDIGO_SUCCESS;
                return process_return;
            } else if (event_type == 2) {
                // we got a wake event, probably the sockets got updated
                // we break form the for loop and then the main loop starts again
                break;
            } else {
                // we got a socket ready
                recv_buffer = mempool->alloc(mempool);
                lret = recvfrom(recv_events[i].data.fd, recv_buffer, sizeof(packet_t) + sizeof(packet_info_t), 0,
                                (struct sockaddr *)(&recv_addr), &recv_addr_len);

                if (lret == -1) {
                    switch (errno) {
                        default:
                            break;
                    }
                    mempool->free(mempool, recv_buffer);
                    break;
                }
                if (lret > sizeof(packet_t) || lret < PAC_MIN_BYTES) {
                    mempool->free(mempool, recv_buffer);
                    continue;
                }
                memcpy(&pack_h, recv_buffer, sizeof(udp_packet_header_t));
                if (pack_h.magic_number != MAGIC_NUMBER_1 || pack_h.magic_number != MAGIC_NUMBER_2) {
                    mempool->free(mempool, recv_buffer);
                    continue;
                }

                ret = queue_push(queue, recv_buffer, QET_NEW_PACKET);
                if (ret) {
                    // the only error is a not enough memory error, so we return an error
                    free(recv_events);
                    mempool->free(mempool, recv_buffer);
                    *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                    return process_return;
                }
                set_event_flag(args->flag, EF_NEW_PACKET);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
            }
        }
    }
    *process_return = 0;
    return process_return;
}
#endif

int *send_thread(SEND_ARGS *args) {
    uint32_t flag_val;
    struct timespec deadline_ts;
    struct timespec current_ts;
    QNODE *node;
    lht_t *active_files = NULL;
    active_file_t *curr_af;
    lht_node_t *list;
    wchar_t username[MAX_USERNAME_LEN];
    int *process_return = NULL;
    int ret;

    // allocate memory for the return value
    process_return = malloc(sizeof(int));
    if (process_return == NULL) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        return NULL;
    }
    *process_return = 0;

    active_files = new_lht(sizeof(active_file_t), sizeof(session_id_t), 1 << 4);
    if (!active_files) {
        set_event_flag(args->flag, EF_TERMINATION);
        set_event_flag(args->wake, EF_WAKE_MANAGER);
        *process_return = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        return process_return;
    }

    ret = load_username(username);
    if (ret) {
        memcpy(username, "remote_device", strlen("remote_device") + 1);
    }

    // the main loop
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

            ret = send_discovery_packets(args->port, args->multicast_addr, args->sockets, args->flag, 3, 150,
                                         args->sign_keys, username);
            if (ret > 0) {
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                delete_lht(active_files);
                *process_return = ret;
                return process_return;
            }
            // returns -1 when we get an override execution or termination event
            if (ret == -1) {
                flag_val = get_event_flag(args->flag);
                if (flag_val & EF_TERMINATION) {
                    delete_lht(active_files);
                    *process_return = 0;
                    return process_return;
                }
            }
        } else if (flag_val & EF_SEND_NEW_FILE) {
            node = queue_pop(args->queue, QOPT_NON_BLOCK);

            if (node == NULL)
                continue;

            if (node->type == QET_SEND_FILE) {
                ret = active_files->insert(active_files, &(((active_file_t *)node->data)->session_id), node->data);
                if (ret) {
                    // todo: do something
                }
            }
            destroy_qnode(node);
            node = NULL;
        }
        // todo: there is a queue node with the info needed, check it and help your self
        else if (flag_val & EF_RESEND_FILE_CHUNK) {
            node = queue_pop(args->queue, QOPT_NON_BLOCK);
            if (node == NULL)
                continue;
            if (node->type == QET_RESEND_FILE_CHUNK) {
                active_file_t *af;
                transmission_control_data_t *data = ((Q_RESEND_FILE_CHUNK *)(node->data))->control;

                af = lht_search(active_files, &(((Q_RESEND_FILE_CHUNK *)(node->data))->session_id));
                if (!af) {
                    free(node->data);
                    destroy_qnode(node);
                    node = NULL;
                    continue;
                }

                for (size_t i = data->first_packet_number; i < data->last_packet_number + 1; i++) {
                    ret = send_file_packet(af, i, args->sign_keys->public, args->sockets, args->flag);
                    if (ret) { // todo: are all errors non recoverable? check it please
                        free(node->data);
                        destroy_qnode(node);
                        node = NULL;
                        set_event_flag(args->flag, EF_TERMINATION);
                        set_event_flag(args->wake, EF_WAKE_MANAGER);
                        delete_lht(active_files);
                        *process_return = ret;
                        return process_return;
                    }
                }
            }

            free(node->data);
            destroy_qnode(node);
            node = NULL;
        } else if (flag_val & EF_STOP_FILE_TRANSMISSION) {
            node = queue_peek(args->queue);
            if (node == NULL)
                continue;
            if (node->type == QET_CONTROL_FILE_TRANSMISSION) {
                queue_remove_front(args->queue);
            }
            free(node->data);
            destroy_qnode(node);
        } // we don't care about other events, if they are there we shouldn't get them anyway

        //////////////////////////////////////////////////
        ///  phase 2: send file and discovery packets  ///
        //////////////////////////////////////////////////

        // send file packets

        // get the list
        ret = lht_list(active_files, &list);

        curr_af = list->data;

        while (curr_af) { // for every active file send a packet, in circular way
            ret = send_next_file_packet(curr_af, args->sign_keys->public, args->sockets, args->flag);
            if (ret) { // todo: are all errors non recoverable? check it please
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                delete_lht(active_files);
                *process_return = ret;
                return process_return;
            }
            // if a file descriptor is null then the file has been transferred
            /*todo: it is a good idea to have a flag, so that if something went wrong in the last packets,
             * we can resend them. we need the fd to do that, so we dont wipe it out. wait something like 3 seconds
             * or have them send a packet for successful transfer or both.
             */
            if (!curr_af->fd) {
                lht_delete(active_files, &(curr_af->session_id));

                // check if we need to send discovery packets
                clock_gettime(CLOCK_REALTIME, &current_ts);
                if (deadline_ts.tv_sec <= current_ts.tv_sec && deadline_ts.tv_nsec <= current_ts.tv_nsec)
                    break;

                // if we remove a node, then curr_af is the next file to be sent
                // if we don't continue we skip curr_af, and it's next packet is not sent
                continue;
            }

            // check if we need to send discovery packets
            clock_gettime(CLOCK_REALTIME, &current_ts);
            if (deadline_ts.tv_sec <= current_ts.tv_sec && deadline_ts.tv_nsec <= current_ts.tv_nsec)
                break;

            list = list->next;
            curr_af = list->data;
        }

        // todo: remove username field if the username is in a file
        ret = send_discovery_packets(args->port, args->multicast_addr, args->sockets, args->flag, 1, 0, args->sign_keys,
                                     username);
        if (ret > 0) {
            set_event_flag(args->flag, EF_TERMINATION);
            set_event_flag(args->wake, EF_WAKE_MANAGER);
            delete_lht(active_files);
            *process_return = ret;
            return process_return;
        }
        // returns -1 when we get an override execution or termination event
        if (ret == -1) {
            flag_val = get_event_flag(args->flag);
            if (flag_val & EF_TERMINATION) {
                delete_lht(active_files);
                *process_return = 0;
                return process_return;
            }
        }
        // set next deadline
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
        lht_list(active_files, &list);
        ret = 0;
        // while there are no more files to send, and we didn't time out and the termination or new file flag is risen
        while (!list && ret == 0 && !(args->flag->event_flag & (EF_TERMINATION | EF_SEND_NEW_FILE))) {
            ret = pthread_cond_timedwait(&(args->flag->cond), &(args->flag->mutex), &deadline_ts);

            if ((ret != ETIMEDOUT) && (ret != 0)) {
                fprintf(stderr, "pthread_cond_timedwait() failed in device_discovery_sending\n");
                set_event_flag(args->flag, EF_TERMINATION);
                set_event_flag(args->wake, EF_WAKE_MANAGER);
                pthread_mutex_unlock(&(args->flag->mutex));
                delete_lht(active_files);
                *process_return = INDIGO_ERROR_INVALID_STATE;
                return process_return;
            }
            if (ret == 0) {
                if (args->flag->event_flag & EF_TERMINATION) {
                    pthread_mutex_unlock(&(args->flag->mutex));
                    delete_lht(active_files);
                    *process_return = 0;
                    return process_return;
                }
            }
        }
        pthread_mutex_unlock(&(args->flag->mutex));
    }

    delete_lht(active_files);
    return process_return;
}
/////////////////////////////////////////////////////////////////
///                                                           ///
///                  THREAD_FUNCTION_HELPERS                  ///
///                                                           ///
/////////////////////////////////////////////////////////////////

#ifdef _WIN32
int create_handle_array_from_recv_info(const RECV_ARRAY *info, HANDLE **handles, size_t *hCount) {
    if (info == NULL || handles == NULL || hCount == NULL)
        return 1;

    RECV_INFO *recv = info->array;
    void *temp = malloc(sizeof(HANDLE) * ((info->size) + 2)); // we allocate 2 more, 1 for the termination handle
    if (temp == NULL)
        return 1; // and one for the wake handle

    *handles = temp;
    *hCount = (info->size) + 2;

    for (int i = 0; i < info->size; i++) {
        (*handles)[2 + i] = recv[i].overlapped->hEvent;
    }

    return 0;
}

void free_recv_array(const RECV_ARRAY *info, mempool_t *mempool) {
    for (int i = 0; i < info->size; i++) {
        free_recv_info(&(info->array[i]), mempool);
    }
    free(info->array);
}
#endif
