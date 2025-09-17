//
// Created by Constantin on 18/08/2025.
//

#include "buffer.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct sbuffer {
    unsigned char *data;
    size_t len;
};

struct lbuffer {
    uint32_t *data;
    size_t len;
};

struct buffer {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    unsigned char *data;
    int len;
    size_t elm_size;
};

SBUF *sbuf_new() {
    return (SBUF *)calloc(1,sizeof(SBUF));
}

void sbuf_free(SBUF *sbuf) {
    free(sbuf->data);
    sbuf->data = NULL;
    free(sbuf);
}

int sbuf_add_elm(SBUF *restrict buffer,const unsigned char data) {
    void *temp;
    if (buffer == NULL) return 1;
    temp = realloc(buffer->data, buffer->len + 1);
    if (temp == NULL) {
        return -1;
    }
    buffer->data = temp;

    buffer->data[buffer->len] = data;
    buffer->len++;
    return 0;
}
int sbuf_add_data(SBUF *restrict buffer, const unsigned char *restrict const data,const size_t len) {
    void *temp;
    if (buffer == NULL) return 1;
    temp = realloc(buffer->data, buffer->len + len);
    if (temp == NULL) {
        return -1;
    }
    memcpy(temp + buffer->len, data, len);
    buffer->data = temp;
    buffer->len += len;
    return 0;
}

int sbuf_get_elm(SBUF *restrict const buffer,const size_t index , unsigned char * restrict const data) {
    if (buffer == NULL) return 1;
    if (index >= buffer->len) return 1;
    *data = (buffer->data)[index];
    return 0;
}

int sbuf_get_data(SBUF *restrict const buffer,const size_t index ,unsigned char **restrict data, size_t *const len) {
    if (buffer == NULL || index >= buffer->len || data == NULL) return 1;

    if (*data == NULL) {
        *data = (unsigned char *)malloc(*len);
        if (*data == NULL) return -1;
    }
    if (*len > (buffer->len - index)) *len = buffer->len - index;

    memcpy(*data, buffer->data + index, *len);
    return 0;
}

int sbuf_set_elm(SBUF *restrict buffer,const size_t index ,const unsigned char data) {
    if (buffer == NULL || index >= buffer->len) return 1;

    (buffer->data)[index] = data;
    return 0;
}

int sbuf_set_data(SBUF *restrict buffer,const size_t index ,const unsigned char *const data, const size_t len) {
    if (buffer == NULL || index >= buffer->len || len > buffer->len - index) return 1;

    memcpy(buffer->data + index, data, len);
    return 0;
}

int sbuf_sort(SBUF *restrict buffer) {
    if (buffer == NULL) return 1;

    qsort(buffer->data, buffer->len, 1,sbuf_cmp);
    return 0;
}

int sbuf_cmp(const void *s1, const void *s2) {
    return memcmp(s1, s2, 1);
}

int sbuf_search(SBUF *restrict buffer, const unsigned char data, size_t *const index) {
    size_t bttm, mid, top;

    if (buffer->len == 0) return -1;

    bttm = 0;
    top = buffer->len;

    while (top > 1){
        mid = top / 2;

        if (data >= (buffer->data)[bttm + mid]) bttm += mid;

        top -= mid;
    }

    if (data == (buffer->data)[bttm]) {
        *index = bttm;
        return 1;
    }
    return 0;
}


LBUF *lbuf_new() {
    return (LBUF *)calloc(1,sizeof(LBUF));
}

void lbuf_free(LBUF *lbuf) {
    free(lbuf->data);
    lbuf->data = NULL;
    free(lbuf);
}

int lbuf_add_elm(LBUF *restrict buffer,const uint32_t data) {
    void *temp;
    if (buffer == NULL) return 1;
    temp = realloc(buffer->data, sizeof(LBUF)*(buffer->len + 1));
    if (temp == NULL) {
        return -1;
    }
    buffer->data = temp;

    buffer->data[buffer->len] = data;
    buffer->len++;
    return 0;
}


int lbuf_get_elm(LBUF *restrict const buffer,const size_t index , uint32_t * restrict const data) {
    if (buffer == NULL) return 1;
    if (index >= buffer->len) return 1;
    *data = (buffer->data)[index];
    return 0;
}


int lbuf_set_elm(LBUF *restrict buffer,const size_t index ,const uint32_t data) {
    if (buffer == NULL || index >= buffer->len) return 1;

    (buffer->data)[index] = data;
    return 0;
}


int lbuf_sort(LBUF *restrict buffer) {
    if (buffer == NULL) return 1;

    qsort(buffer->data, buffer->len, 1,sbuf_cmp);
    return 0;
}

int lbuf_cmp(const void *s1, const void *s2) {
    return memcmp(s1, s2, 1);
}

int lbuf_search(LBUF *restrict buffer, const uint32_t data, size_t *const index) {
    size_t bttm, mid, top;

    if (buffer->len == 0) return -1;

    bttm = 0;
    top = buffer->len;

    while (top > 1){
        mid = top / 2;

        if (data >= (buffer->data)[bttm + mid])
            bttm += mid;

        top -= mid;
    }

    if (data == (buffer->data)[bttm]) {
        if (index != NULL) *index = bttm;
        return 1;
    }
    return 0;
}