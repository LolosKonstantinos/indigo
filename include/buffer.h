//
// Created by Constantin on 18/08/2025.
//

#ifndef BUFFER_H
#define BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct sbuffer SBUF;
typedef struct lbuffer LBUF;
typedef struct buffer BUF;

SBUF *sbuf_new();
void sbuf_free(SBUF *sbuf);

int sbuf_add_elm(SBUF *restrict buffer,unsigned char data);
int sbuf_add_data(SBUF *restrict buffer, const unsigned char *restrict data,size_t len);
int sbuf_get_elm(SBUF *restrict buffer,size_t index , unsigned char * restrict data);
int sbuf_get_data(SBUF *restrict buffer,size_t index ,unsigned char **restrict data, size_t *len);
int sbuf_set_elm(SBUF *restrict buffer,size_t index ,unsigned char data);
int sbuf_set_data(SBUF *restrict buffer,size_t index ,const unsigned char *data, size_t len);
int sbuf_sort(SBUF *restrict buffer);
int sbuf_cmp(const void *s1, const void *s2);
int sbuf_search(SBUF *restrict buffer, unsigned char data, size_t *index);


LBUF *lbuf_new();
void lbuf_free(SBUF *sbuf);
int lbuf_add_elm(LBUF *restrict buffer,const uint32_t data);
int lbuf_get_elm(LBUF *restrict buffer,size_t index , uint32_t * restrict data);
int lbuf_set_elm(LBUF *restrict buffer,const size_t index ,const uint32_t data);
int lbuf_sort(LBUF *restrict buffer);
int lbuf_cmp(const void *s1, const void *s2);
int lbuf_search(LBUF *restrict buffer, const uint32_t data, size_t *const index);
#endif //BUFFER_H



