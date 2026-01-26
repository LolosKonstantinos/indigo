//
// Created by Κωνσταντίνος on 4/16/2025.
//

#include "indigo_core/indigo_core.h"
#include "buffer.h"
#include "indigo_errors.h"
#include <stdlib.h>
#include <errno.h>
#include <sodium.h>
#include "crypto_utils.h"

//todo split this library to the device discovery and the receiving and managing part
//todo ip banning should be done to the kernel level





////////////////////////////////////////////////////////////////////
///                                                              ///
///                  general_use_functions/misc                  ///
///                                                              ///
////////////////////////////////////////////////////////////////////

void print_discovered_device_info(const PACKET_INFO *dev, FILE *stream) {
    char addr_str[INET_ADDRSTRLEN];
    struct sockaddr_in address = dev->address;
    inet_ntop(AF_INET,&(address.sin_addr.S_un.S_addr),addr_str,INET_ADDRSTRLEN);

    fprintf(stream, "Hostname: ");

    // for (int i = 0; i < MAX_HOSTNAME_LEN; i++) {
    //     if ((dev->hostname[i]) != '\0')fprintf(stream, "%c", dev->hostname[i]);
    // }
    fprintf(stream, "\n");

    fprintf(stream, "IP Address: %s\n",addr_str);

    fprintf(stream,"MAC ADDRESS: ");
    for (uint8_t i = 0; i<dev->mac_address_len; i++) {
        fprintf(stream,"%02x",dev->mac_address[i]);
        if (i != dev->mac_address_len - 1) fprintf(stream,":");
    }
    fprintf(stream,"\n");

    fprintf(stream, "Timestamp: %lld\n\n", dev->timestamp);
    fflush(stream);
}


//////////////////////////////////////////////////////////////
///                                                        ///
///                  DEVICE_LL_UTILITIES                   ///
///                                                        ///
//////////////////////////////////////////////////////////////

int remove_device(PACKET_LIST *devices, const PACKET_INFO *dev) {
    if (devices == NULL) return 1;


    PACKET_NODE *prev = NULL;
    PACKET_NODE *curr = devices->head;

    while (curr != NULL) {
        if (memcmp(curr->packet.mac_address, dev->mac_address, 6) == 0) {
            if (prev == NULL) {
                devices->head = curr->next;
                free(curr);
                return 0;
            }

            prev->next = curr->next;
            free(curr);
            return 0;

        }
        prev = curr;
        curr = curr->next;
    }
    return -1;
}

PACKET_NODE *device_exists(const PACKET_LIST *devices, const PACKET_INFO *dev) {
    if (devices == NULL) return NULL;

    for (PACKET_NODE *curr = devices->head; curr != NULL; curr = curr->next) {
        if (memcmp(curr->packet.mac_address, dev->mac_address, 6) == 0) return curr;
    }
    return NULL;
}