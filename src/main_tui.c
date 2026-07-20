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

#include "tui/tui.h"
#include "binary_tree.h"
#include "indigo_errors.h"
#include "Queue.h"
#include "config.h"
#include "indigo_core/net_io.h"
#include "indigo_types.h"
#include "logger.h"
#include "manager.h"
#include <log.h>

#include <locale.h>
#include <stdio.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

int main(int argc, char *argv[])
{
#ifdef _WIN32
    WSADATA wsaData;
#endif
    int ret = 0;

    // network
    int port;
    uint32_t multicast_addr;
    struct in_addr maddr;

    // device table
    tree_t *device_tree;
    // the file tree
    tree_t *file_tree;

    // ui queue
    QUEUE *ui_queue;

    // the packet handler queue
    QUEUE *ph_queue = NULL;
    // the send queue
    QUEUE *send_queue = NULL;
    // the manager queue
    QUEUE *manager_queue = NULL;

    MANAGER_ARGS *manager_args;
    pthread_t manager_tid;
    void *master_key;

    FILE *log_file = NULL;

    logger_init();
    log_file = load_log_file();
    if (log_file == NULL) {
        return -1;
    }
    log_add_fp(log_file, LOG_TRACE);

    if (sodium_init() == -1)
        return INDIGO_ERROR_SODIUM_ERROR;

#ifdef _WIN32
    ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    setlocale(LC_ALL, "");
    initscr();
    // todo learn how to use color
    cbreak();
    noecho();

    // verify the user, check if crypto files are ready to go, and check password
    // ret = verify_user(&master_key);
    // if (ret != 0) {
    //     goto cleanup;
    // }
    bypass_password(&master_key);
    // create the device tree

    ret = new_tree(&device_tree, cmp_rdev, sizeof(remote_device_t), BINARY_TREE_FLAG_AVL);
    if (ret) {
        fprintf(stderr, "malloc failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    ret = new_tree(&file_tree, cmp_ui_file, sizeof(ui_file_t), BINARY_TREE_FLAG_AVL);
    if (ret) {
        fprintf(stderr, "malloc failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    ui_queue = malloc(sizeof(QUEUE));
    if (ui_queue == NULL) {
        fprintf(stderr, "malloc failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    ret = init_queue(ui_queue);
    if (ret) {
        fprintf(stderr, "init_queue failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    send_queue = malloc(sizeof(QUEUE));
    if (send_queue == NULL) {
        fprintf(stderr, "malloc failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    ret = init_queue(send_queue);
    if (ret) {
        fprintf(stderr, "init_queue failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    ph_queue = (QUEUE *)malloc(sizeof(QUEUE));
    if (ph_queue == NULL) {
        fprintf(stderr, "Failed to allocate memory for packet_queue\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    if (init_queue(ph_queue)) {
        fprintf(stderr, "init_queue failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    manager_queue = malloc(sizeof(QUEUE));
    if (manager_queue == NULL) {
        fprintf(stderr, "malloc failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }
    ret = init_queue(manager_queue);
    if (ret) {
        fprintf(stderr, "init_queue failed\n");
        ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
        goto cleanup;
    }

    inet_pton(AF_INET, MULTICAST_ADDR, &multicast_addr);
    port = PORT;

    ret = create_thread_manager_thread(&manager_args, master_key, port, multicast_addr, device_tree, ui_queue, ph_queue,
                                       send_queue, manager_queue, &manager_tid);
    if (ret != INDIGO_SUCCESS) {
        fprintf(stderr, "Error creating thread_manager thread\n");
        goto cleanup;
    }

    // create the main tui interface
    init_pair(1, COLOR_RED, COLOR_BLACK);
    init_pair(2, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(3, COLOR_YELLOW, COLOR_BLACK);
    init_pair(4, COLOR_GREEN, COLOR_BLACK);
    init_pair(5, COLOR_CYAN, COLOR_BLACK);
    init_pair(6, COLOR_BLUE, COLOR_BLACK);

    init_pair(7, COLOR_RED, COLOR_WHITE);
    init_pair(8, COLOR_MAGENTA, COLOR_WHITE);
    init_pair(9, COLOR_YELLOW, COLOR_WHITE);
    init_pair(10, COLOR_GREEN, COLOR_WHITE);
    init_pair(11, COLOR_CYAN, COLOR_WHITE);
    init_pair(12, COLOR_BLUE, COLOR_WHITE);
    init_pair(12, COLOR_BLACK, COLOR_WHITE);

    create_main_interface(device_tree, file_tree, ui_queue, ph_queue, send_queue);

    endwin();
    printf("\nmain return:%d\n", ret);
    getchar();
    return ret;

cleanup:
#ifdef _WIN32
    WSACleanup();
#endif
    endwin();
    return ret;
}
