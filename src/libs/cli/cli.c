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
#include "cli.h"
#include <stdio.h>

#ifdef WIN32
#include <windef.h>
#include <Winbase.h>
#include <WinCon.h>
#else
/*assume Linux*/
#include <sys/ioctl.h>
#include <unistd.h>
#endif

struct progress_bar_t {
    int x;
    int y;
    int width;
    char percentage;
    char zero[3];
};

int get_src_size(int *rows, int *cols) {
#ifdef WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;

    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info) == 0)
        return -1;

    *rows = info.dwSize.Y;
    *cols = info.dwSize.X;
#else
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    
    *rows = w.ws_row;
    *cols = w.ws_col;
#endif
    return 0;
}

void clear_screen() {
    printf("\033[2J\033[H");
}

int new_progress_bar(progress_bar_t **progress_bar) {
    progress_bar_t *new_progress_bar;
    new_progress_bar = malloc(sizeof(progress_bar_t));
    if (new_progress_bar == NULL) {
        *progress_bar = NULL;
        return -1;
    }

    new_progress_bar->x = 0;
    new_progress_bar->y = 0;
    new_progress_bar->width = 0;
    new_progress_bar->percentage = 0;

    *progress_bar = new_progress_bar;
    return 0;
}
int delete_progress_bar(progress_bar_t **progress_bar) {

}
int update_progress_bar(progress_bar_t *progress_bar, char progress) {

}
int move_progress_bar(progress_bar_t *progress_bar, int x, int y) {

}