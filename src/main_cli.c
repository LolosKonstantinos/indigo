#include <locale.h>
#include <stdio.h>
#include <unistd.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "indigo_core/net_io.h"
#include "file_transfer.h"
#include <cli/cli.h>
#include "crypto_utils.h"
#include "manager.h"


int main(int argc, char *argv[]) {
    MANAGER_ARGS *managerArgs;
    pthread_t manager_tid;

    setlocale(LC_ALL, "");
    initscr();
    //todo learn how to use color
    init_pair(1, COLOR_RED, COLOR_BLACK);
    cbreak();
    noecho();

    //verify the user, check if crypto files are ready to go, and check password
    int ret = verify_user(); //todo: modify to create the maser key, and with it create signing keys
    if (ret != 0) {
        endwin();
        return 1;
    }

    //todo import from network config the ports and multicast addresses
    ret = create_thread_manager_thread(&managerArgs, PORT, MULTICAST_ADDR,&manager_tid);
    if (ret != 0) {
        fprintf(stderr, "Error creating thread_manager thread\n");
        endwin();
        return 1;
    }


    getchar();
    endwin();
    free(managerArgs);//remove later manager frees their args
    return ret;
}
