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

#include <locale.h>
#include <stdio.h>
#include <unistd.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "indigo_core/net_io.h"
#include <cli/cli.h>
#include "crypto_utils.h"
#include "indigo_types.h"
#include "manager.h"

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    int ret;

    //network
    int port;
    uint32_t multicast_addr;

    //device table
    tree_t *device_tree;

    MANAGER_ARGS *manager_args;
    pthread_t manager_tid;
    void *master_key;

    ret = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (ret != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    if (sodium_init() == -1) return 1;
    setlocale(LC_ALL, "");
    initscr();
    //todo learn how to use color
    init_pair(1, COLOR_RED, COLOR_BLACK);
    cbreak();
    noecho();

    //verify the user, check if crypto files are ready to go, and check password
    ret = verify_user(&master_key);
    if (ret != 0) {
        endwin();
        WSACleanup();
        printf("\nverify_user failed\n");
        return ret;
    }


    //create the device ll

    ret = new_tree(&device_tree, cmp_rdev, sizeof(remote_device_t), BINARY_TREE_TYPE_AVL);
    if (!ret) {
        fprintf(stderr, "malloc failed\n");
        endwin();
        WSACleanup();
        return ret;
    }

    // todo import from network config the ports and multicast addresses
    inet_pton(AF_INET, MULTICAST_ADDR,&multicast_addr);
    port = (int) htonl(PORT);
    ret = create_thread_manager_thread(&manager_args, port, multicast_addr, device_tree, &manager_tid);
    if (ret != 0) {
        fprintf(stderr, "Error creating thread_manager thread\n");
        endwin();
        WSACleanup();
        return 1;
    }

    //create the main cli interface
    create_main_interface(device_tree);

    endwin();
    printf("\nmain return:%d\n", ret);
    getchar();
    return ret;
}
