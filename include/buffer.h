//
// Created by Constantin on 18/08/2025.
//

#ifndef BUFFER_H
#define BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct sbuffer SBUF;
typedef struct lbuffer LBUF;
typedef struct llbuffer LLBUF;
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
void lbuf_free(LBUF *sbuf);
int lbuf_add_elm(LBUF *restrict buffer, uint32_t data);
int lbuf_get_elm(LBUF *restrict buffer,size_t index , uint32_t * restrict data);
int lbuf_set_elm(LBUF *restrict buffer, size_t index , uint32_t data);
int lbuf_sort(LBUF *restrict buffer);
int lbuf_cmp(const void *s1, const void *s2);
int lbuf_search(LBUF *restrict buffer, uint32_t data, size_t * index);

LLBUF *llbuf_new();
void llbuf_free(LLBUF *restrict buffer);
int llbuf_add_elm(LLBUF *restrict buffer, uint64_t data);
int llbuf_get_elm(LLBUF *restrict buffer,size_t index , uint64_t * restrict data);
int llbuf_set_elm(LLBUF *restrict buffer, size_t index , uint64_t data);
int llbuf_sort(LLBUF *restrict buffer);
int llbuf_cmp(const void *s1, const void *s2);
int llbuf_search(LLBUF *restrict buffer, uint64_t data, size_t * index);

BUF *new_buffer(size_t cell_size, size_t cell_count);
void free_buffer(BUF *buffer);
int buffer_get(BUF *restrict buffer,size_t index , unsigned char * restrict data);
int buffer_get_reference(BUF *restrict buffer,size_t index ,unsigned char ** restrict data);
int buffer_set(BUF *restrict buffer,size_t index ,const unsigned char *restrict data);
int buffer_dynamic_set(BUF *buffer,size_t index ,const unsigned char *restrict data);

int buffer_optimize(BUF *restrict buffer);
#endif //BUFFER_H



