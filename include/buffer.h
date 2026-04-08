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



