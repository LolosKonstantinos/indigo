//
// Created by Constantin on 08/04/2026.
//
#include <config.h>

#include "indigo_errors.h"

int load_username(wchar_t username[MAX_USERNAME_LEN]) {
    size_t ret;
    int size;
    FILE *fd = fopen(strcat(INDIGO_USER_DIR, INDIGO_USERNAME_FILE_NAME), "rb");
    if (!fd) {
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    fseek(fd, 0, SEEK_END);
    size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    memset(username, 0, sizeof(wchar_t) * MAX_USERNAME_LEN);

    ret = fread(username, 1, MAX_USERNAME_LEN * sizeof(wchar_t), fd);
    if (ret != size) {

        fclose(fd);
        return INDIGO_ERROR;
        //todo: handle error better
    }
    return 0;
}

int set_username(wchar_t username[MAX_USERNAME_LEN]) {
    size_t ret;
    FILE *fd = fopen(strcat(INDIGO_USER_DIR, INDIGO_USERNAME_FILE_NAME), "wb");
    if (!fd) {
        return INDIGO_ERROR_CAN_NOT_OPEN_FILE;
    }
    ret = fwrite(username, 1, MAX_USERNAME_LEN * sizeof(wchar_t), fd);
    if (ret != MAX_USERNAME_LEN) {
        fclose(fd);
        return INDIGO_ERROR;
        //todo: handle error better
    }
    fclose(fd);
    return 0;
}