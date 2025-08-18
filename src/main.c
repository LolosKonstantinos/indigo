#include <stdio.h>
#include <unistd.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "device_discovery.h"
#include "file_transfer.h"

#include "crypto_utils.h"


int main(int argc, char *argv[]) {
    // int ret;
    // printf("DEBUG:\n");
    // fflush(stdout);
    //
    // ret = create_key_derivation_settings();
    // printf("Created key derivation settings: %d\n", ret);
    // fflush(stdout);

    WSADATA wsaData;
    int err;
    uint8_t derr;
    uint32_t multicast_address;
    pthread_t tid;
    MANAGER_ARGS *args;
    DEVICE_LIST *devices;

    printf("WELCOME\n");

    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        WSACleanup();
        return 1;
    }

    inet_pton(AF_INET, MULTICAST_ADDR, &multicast_address);

    devices = (DEVICE_LIST *) malloc(sizeof(DEVICE_LIST));
    if (devices == NULL) {
        printf("malloc failed\n");
        WSACleanup();
        return 1;
    }
    devices->head = NULL;
    pthread_mutex_init(&devices->mutex, NULL);
    pthread_cond_init(&devices->cond, NULL);

    derr = init_device_discovery(&args,htons(DISCOVERY_PORT),multicast_address,devices,&tid);
    if (derr != 0) {
        printf("init_device_discovery failed with error: %d\n", derr);
        WSACleanup();
        return 1;
    }

    printf("init_device_discovery done\n");
    // for (int i = 0; i<5; i++) {
    //     printf("%d\n", 5-i);
    //     sleep(1);
    // }

    sleep(120);

    derr = cancel_device_discovery(tid,args->flag);
    printf("Device discovery finished: %x\n", derr);
    fflush(stdout);
    WSACleanup();
    return 0;
}