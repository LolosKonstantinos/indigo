#include <stdio.h>
#include <unistd.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "indigo_core/indigo_core.h"
#include "file_transfer.h"
#include <cli/cli.h>
#include "crypto_utils.h"


int main(int argc, char *argv[]) {
    // int ret;
    // printf("DEBUG:\n");
    // fflush(stdout);
    //
    // ret = create_key_derivation_settings();
    // printf("Created key derivation settings: %d\n", ret);
    // fflush(stdout);
    // getchar();
    initscr();
    create_new_password();
    endwin();
    return 0;
}