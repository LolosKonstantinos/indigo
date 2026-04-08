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