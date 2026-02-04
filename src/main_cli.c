#include <locale.h>
#include <stdio.h>
#include <unistd.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "indigo_core/net_io.h"
#include "file_transfer.h"
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
    hash_table_t *device_table;

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
        return ret;
    }

    //create the device table
    device_table = new_hash_table(sizeof(remote_device_t), crypto_sign_PUBLICKEYBYTES, 1<<4);
    // todo import from network config the ports and multicast addresses
    inet_pton(AF_INET, MULTICAST_ADDR,&multicast_addr);
    port = (int) htonl(PORT);
    ret = create_thread_manager_thread(&manager_args, port, multicast_addr, device_table, &manager_tid);
    if (ret != 0) {
        fprintf(stderr, "Error creating thread_manager thread\n");
        endwin();
        WSACleanup();
        return 1;
    }

    //create the main cli interface


    endwin();
    WSACleanup();
    printf("\nmain return:%d\n", ret);
    getchar();
    return ret;
}
