//
// Created by Constantin on 20/08/2025.
//

#ifndef INDIGO_ERRORS_H
#define INDIGO_ERRORS_H

static int indigo_last_error = 0;

inline int indigo_get_last_error() {
    return indigo_last_error;
}

inline void indigo_set_error(int err) {
    indigo_last_error = err;
}

#define INDIGO_SUCCESS 0
#define INDIGO_ERROR 1

//positive values are for errors the programmer or the system caused
#define INDIGO_ERROR_SYS_FAIL 2
#define INDIGO_ERROR_MEMORY_ERROR 3
#define INDIGO_ERROR_INVALID_PARAM 4
#define INDIGO_ERROR_INVALID_STATE 5
#define INDIGO_ERROR_UNSUPPORTED 6
#define INDIGO_ERROR_WINLIB_ERROR 7
#define INDIGO_ERROR_SODIUM_ERROR 8
#define INDIGO_ERROR_TIMEOUT 9
#define INDIGO_ERROR_FILE_NOT_FOUND 10

//negative values are for errors the user or a peer caused
#define INDIGO_ERROR_INVALID_INPUT -1
#define INDIGO_ERROR_INCOMPATIBLE_FILE -2
#define INDIGO_ERROR_FALSE_SIGNATURE -3
#define INDIGO_ERROR_FALSE_KEY -4
#define INDIGO_ERROR_PEER_DISCONNECTED -5
#define INDIGO_ERROR_PEER_TIMEOUT -6
#define INDIGO_ERROR_WRONG_PASSWORD -7
#define INDIGO_ERROR_INVALID_PACKET -8

#endif //INDIGO_ERRORS_H
