/*
Copyright (c) 2026 Lolos Konstantinos

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

#ifndef INDIGO_CLI_H
#define INDIGO_CLI_H
#include "indigo_types.h"
#include "Queue.h"
#include "binary_tree.h"

#ifdef _WIN32
typedef BOOL (*WIN_CONSOLE_INPUT)(HANDLE, PINPUT_RECORD, DWORD, LPDWORD, USHORT);
#endif

typedef struct progress_bar_t progress_bar_t;

int get_src_size(int *rows, int *cols);

void clear_screen();
void delete_lines(int count);

//progress bar utilities

int new_progress_bar(progress_bar_t **progress_bar);
int delete_progress_bar(progress_bar_t **progress_bar);
int update_progress_bar(progress_bar_t *progress_bar, char progress);
int move_progress_bar(progress_bar_t *progress_bar, int x, int y);
int refresh_progress_bar(progress_bar_t *progress_bar);

//login utilities
//this function is only for testing environments with password set to "test" and needs all parameters set
void bypass_login(void **master_key);
int isspecialchar(char ch);
int password_is_valid(char psw[MAX_PSW_LEN + 1]);
int create_new_password();
int login(void **master_key);
int create_main_loop(tree_t *device_tree, QUEUE *ui_queue);
int is_special_key(char key);
#ifdef _WIN32
int get_next_input(char *input, char echo, WIN_CONSOLE_INPUT ReadConsoleInputExA);
#endif

#endif //INDIGO_CLI_H
