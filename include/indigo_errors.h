//
// Created by Constantin on 20/08/2025.
//

#ifndef INDIGO_ERRORS_H
#define INDIGO_ERRORS_H

#define INDIGO_SUCCESS 0
#define INDIGO_ERROR 1

//positive values are for errors the programmer or the system caused
#define INDIGO_ERROR_SYS_FAIL                 2
#define INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR  3
#define INDIGO_ERROR_INVALID_PARAM            4
#define INDIGO_ERROR_INVALID_STATE            5 //this is a bug state of the application, a "bug state" essentially
#define INDIGO_ERROR_UNSUPPORTED              6
#define INDIGO_ERROR_WINLIB_ERROR             7
#define INDIGO_ERROR_SODIUM_ERROR             8
#define INDIGO_ERROR_TIMEOUT                  9
#define INDIGO_ERROR_FILE_NOT_FOUND           10
#define INDIGO_ERROR_NO_ADDRESS_FOUND         11 //this error is for when there is no available active address
#define INDIGO_ERROR_WINSOCK2_NOT_INITIALIZED 12
#define INDIGO_ERROR_NETWORK_SUBSYS_DOWN      13 //serious error we need to terminate the application

//negative values are for errors the user or a peer caused
#define INDIGO_ERROR_INVALID_INPUT     -1
#define INDIGO_ERROR_INCOMPATIBLE_FILE -2
#define INDIGO_ERROR_FALSE_SIGNATURE   -3
#define INDIGO_ERROR_FALSE_KEY         -4
#define INDIGO_ERROR_PEER_DISCONNECTED -5
#define INDIGO_ERROR_PEER_TIMEOUT      -6
#define INDIGO_ERROR_WRONG_PASSWORD    -7
#define INDIGO_ERROR_INVALID_PACKET    -8

#endif //INDIGO_ERRORS_H
