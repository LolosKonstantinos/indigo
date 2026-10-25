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

#include "ui.h"
#include "queue.h"
#include "binary_tree.h"
#include "crypto_utils.h"
#include "indigo_core/net_io.h"
#include "indigo_errors.h"
#include "indigo_types.h"
#include <config.h>
#include <glib-2.0/glib.h>
#include <glib-2.0/glib/gstdio.h>
// #include <ncursesw/curses.h>
#include <curses.h>
#include <pthread.h>
#include <sodium/crypto_sign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wctype.h>
#include <uchar.h>
#include <errno.h>
#include <log.h>
#include <indigo_api/indigo_api.h>

#ifdef _WIN32
#define sleep(t) (Sleep(1000 * t))
#include <winsock2.h>
#endif


int get_user_input(WINDOW *win, utf8_char_t *input)
{
    int ret = 0;
    wint_t c = 0;
#ifdef _WIN32
    mbstate_t state = {0};
    *input = 0;
    ret = wget_wch(win, &c);
    if (ret == OK) {
        ret = c16rtomb((char *)input, c, &state);
        switch (ret) {
            case (int)((size_t)(-1)):
                return -1;
            case 0:
                ret = wget_wch(win, &c);
                if (ret == OK) {
                    ret = c16rtomb((char *)input, c, &state);
                    if (ret == ((size_t)(-1)))
                        return -1;
                    else {
                        return OK;
                    }
                }
                else if (ret == KEY_CODE_YES) {
                    *input = c;
                    return KEY_CODE_YES;
                }
                else {
                    return -1;
                }
                break;
            default:
                break;
        }
    }
    else if (ret == KEY_CODE_YES) {
        *input = c;
        return KEY_CODE_YES;
    }
    return -1;
#else
    *input = 0;
    ret = wget_wch(win, &c);
    if (ret == OK) {
        wctomb((char *)input, (wchar_t)c);
        return OK;
    }
    else if (ret == KEY_CODE_YES) {
        *input = c;
        return KEY_CODE_YES;
    }
    return -1;
#endif
}

int pathfinder(char path[PATH_MAX])
{
    utf8_char_t in_char;
    char in_path[PATH_MAX] = {0};
    char *initial_cwd = NULL;
    int in_path_len = 0;
    int ret = 0;
    int64_t lret = 0;
    GDir *curr_dir = NULL;
    GError *err = NULL;
    const char *dir_entry = NULL;
    char *cpath = NULL;
    char *cwd = NULL;
    WINDOW *win;
    WINDOW *win_frame;
    WINDOW *win_text;
    int maxx;
    int maxy;
    int win_c; // this is the visible window width
    int win_r; // this is the visible window height
    const int win_init_c = 120;
    const int win_init_r = 500;
    int x;
    int y;
    int entry_num = 0;
    int win_origin_x = 0;
    int win_origin_y = 0;

    getmaxyx(stdscr, maxy, maxx);
    win_c = maxx - 2;
    win_r = maxy - 5; // we do -3 to make room for the text input
    win = newpad((win_r > win_init_r) ? win_r : win_init_r, (win_c > win_init_c) ? win_c : win_init_c);
    win_frame = newwin(maxy, maxx, 0, 0);

    win_text = newwin(3, win_c, maxy - 4, 1);

    box(win_frame, 0, 0);
    box(win_text, 0, 0);

    wnoutrefresh(win_frame);
    wnoutrefresh(win_text);
    x = 0;
    y = 0;
    wattron(win, COLOR_PAIR(2));
    mvwprintw(win, y, x, "Enter . to select the cwd, or a filename to select the respective file.");
    ++y;
    mvwprintw(win, y, x, "Use ESC (escape) to quit this dialog.");
    ++y;
    wattroff(win, COLOR_PAIR(2));

    keypad(win_text, TRUE);
    curs_set(1);
    cbreak();

    initial_cwd = g_get_current_dir();

    cwd = g_get_current_dir();
    if (cwd) {
        wattron(win, COLOR_PAIR(5));
        mvwprintw(win, y, x, "Current directory: %s", cwd);
        wattroff(win, COLOR_PAIR(5));
        y += 2;
        pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);
        g_free(cwd);
    }
    cwd = NULL;

    curr_dir = g_dir_open(".", 0, &err);
    if (err) {
        // TODO: check error codes
        log_warn("g_dir_open failed: %s", err->message);
        g_clear_error(&err);
        return -1;
    }
    // print the current directory

    dir_entry = g_dir_read_name(curr_dir);
    while (dir_entry) {
        cpath = g_canonicalize_filename(dir_entry, NULL);
        if (!cpath) {
            g_chdir(initial_cwd);
            g_free(initial_cwd);
            g_dir_close(curr_dir);
            g_free(cpath);
            delwin(win);
            delwin(win_frame);
            delwin(win_text);
            log_error("g_canonicalize_filename() failed | return -1");
            return -1;
        }
        ret = g_file_test(cpath, G_FILE_TEST_EXISTS);
        if (ret == 0) {
            g_free(cpath);
            cpath = NULL;
            continue;
        }
        ret = g_file_test(cpath, G_FILE_TEST_IS_DIR);
        if (ret) {
            // if it is a directory print it in blue
            wattron(win, COLOR_PAIR(6) | A_BOLD);
            mvwprintw(win, y, x, "%s", dir_entry);
            wattroff(win, COLOR_PAIR(6) | A_BOLD);
            ++y;
        }
        else {
            // if it is a file or symlink print it in green
            wattron(win, COLOR_PAIR(4) | A_BOLD);
            mvwprintw(win, y, x, "%s", dir_entry);
            wattroff(win, COLOR_PAIR(4) | A_BOLD);
            ++y;
        }
        g_free(cpath);
        cpath = NULL;
        dir_entry = g_dir_read_name(curr_dir);
        ++entry_num;
    }
    g_dir_close(curr_dir);
    pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);
    wmove(win_text, 1, 1);
    doupdate();

    while (1) {
        // get user input
        ret = get_user_input(win_text, &in_char);

        if (ret == OK) {
            if (in_char == '\x1b') {
                // if it is escape we exit
                g_chdir(initial_cwd);
                g_free(initial_cwd);
                memset(path, 0, PATH_MAX);
                delwin(win);
                delwin(win_frame);
                delwin(win_text);
                return 1;
            }
            else if (in_char == '\n' || in_char == '\r') {
                // we support full paths
                // we support relative paths
                // enter goes to the path
                // if the path is "." we select the current path
                // TODO: use tab to autocomplete
                cpath = g_canonicalize_filename(in_path, NULL);
                if (!cpath) {
                    g_chdir(initial_cwd);
                    g_free(initial_cwd);
                    delwin(win);
                    delwin(win_frame);
                    delwin(win_text);
                    log_error("g_canonicalize_filename() failed | return -1");
                    return -1;
                }

                // check if the user entered the current path to select it
                cwd = g_get_current_dir();
                if (strcmp(cwd, cpath) == 0) {
                    g_chdir(initial_cwd);
                    g_free(initial_cwd);
                    g_utf8_strncpy(path, cpath, g_utf8_strlen(cpath, -1));
                    g_free(cwd);
                    g_free(cpath);
                    delwin(win);
                    delwin(win_frame);
                    delwin(win_text);
                    return 0;
                }
                g_free(cwd);

                // check if the file exists
                if (g_file_test(cpath, G_FILE_TEST_EXISTS) == 0) {
                    // either path is a file, or path is invalid.
                    //  the path is not valid or cannot be g_access
                    //  print error and Re-enter
                    wclear(win_text);
                    box(win_text, 0, 0);
                    wattron(win_text, COLOR_PAIR(3));
                    mvwprintw(win_text, 1, 1, "Entered path is not valid or inaccesible! Try again!");
                    wnoutrefresh(win_text);
                    wattroff(win_text, COLOR_PAIR(3));

                    doupdate();
                    in_path_len = 0;
                    memset(in_path, 0, PATH_MAX);
                    g_free(cpath);
                    cpath = NULL;
                    continue;
                }

                if (g_file_test(cpath, G_FILE_TEST_IS_REGULAR)) {
                    // we just select the file
                    g_chdir(initial_cwd);
                    g_free(initial_cwd);
                    g_utf8_strncpy(path, cpath, g_utf8_strlen(cpath, -1));
                    g_free(cpath);
                    delwin(win);
                    delwin(win_frame);
                    delwin(win_text);
                    return 0;
                }
                if (g_chdir(cpath)) {
                    // either path is a file, or path is invalid.
                    //  the path is not valid or cannot be g_access
                    //  print error and Re-enter
                    wclear(win_text);
                    box(win_text, 0, 0);
                    wattron(win_text, COLOR_PAIR(3));
                    mvwprintw(win_text, 1, 1, "Entered path is not valid or inaccesible! Try again!");
                    wrefresh(win_text);
                    wattroff(win_text, COLOR_PAIR(3));

                    in_path_len = 0;
                    memset(in_path, 0, PATH_MAX);
                    g_free(cpath);
                    cpath = NULL;
                    continue;
                }

                g_free(cpath);
                cpath = NULL;

                // print the current directory
                wclear(win);
                win_origin_y = 3;
                x = 1;
                y = 1;
                wattron(win, COLOR_PAIR(2));
                mvwprintw(win, y, x, "Enter . to select the cwd, or a filename to select the respective file.");
                ++y;
                mvwprintw(win, y, x, "Use ESC (escape) to quit this dialog.");
                ++y;
                wattroff(win, COLOR_PAIR(2));

                cwd = g_get_current_dir();
                if (!cwd) {
                    // this is probably a memory error
                    g_chdir(initial_cwd);
                    g_free(initial_cwd);
                    delwin(win);
                    delwin(win_frame);
                    delwin(win_text);
                    log_error("g_get_current_dir() failed | return -1");
                    return -1;
                }
                wattron(win, COLOR_PAIR(5));
                mvwprintw(win, y, x, "Current directory: %s", cwd);
                wattroff(win, COLOR_PAIR(5));
                y += 2;
                g_free(cwd);

                entry_num = 0;
                curr_dir = g_dir_open(".", 0, &err);
                if (err) {
                    // TODO: check error codes, we don't want to print plain errors. error handle bbetter
                    g_printerr("%s", err->message);
                    g_clear_error(&err);
                }
                dir_entry = g_dir_read_name(curr_dir);

                while (dir_entry) {
                    cpath = g_canonicalize_filename(dir_entry, NULL);
                    if (!cpath) {
                        g_chdir(initial_cwd);
                        g_free(initial_cwd);
                        g_dir_close(curr_dir);
                        delwin(win);
                        delwin(win_frame);
                        delwin(win_text);
                        log_error("g_canonicalize_filename() failed | return -1");
                        return -1;
                    }
                    ret = g_file_test(cpath, G_FILE_TEST_EXISTS);
                    if (ret == 0) {
                        g_free(cpath);
                        cpath = NULL;
                        continue;
                    }
                    ret = g_file_test(cpath, G_FILE_TEST_IS_DIR);
                    if (ret) {
                        // if it is a directory print it in blue
                        wattron(win, COLOR_PAIR(6) | A_BOLD);
                        mvwprintw(win, y, x, "%s", dir_entry);
                        wattroff(win, COLOR_PAIR(6) | A_BOLD);
                        ++y;
                    }
                    else {
                        // if it is a file or symlink print it in green
                        wattron(win, COLOR_PAIR(4) | A_BOLD);
                        mvwprintw(win, y, x, "%s", dir_entry);
                        wattroff(win, COLOR_PAIR(4) | A_BOLD);
                        ++y;
                    }
                    g_free(cpath);
                    cpath = NULL;
                    dir_entry = g_dir_read_name(curr_dir);
                    ++entry_num;
                }
                g_dir_close(curr_dir);
                pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);
                werase(win_text);
                box(win_text, 0, 0);
                wmove(win_text, 1, 1);
                wnoutrefresh(win_text);
                in_path_len = 0;
                memset(in_path, 0, PATH_MAX);
            }
            else if (PATH_MAX - strlen(in_path) - 1 > 4) {
                // TODO: validate the character

                strcat(in_path, (char *)&in_char);
                ++in_path_len;
                werase(win_text);
                box(win_text, 0, 0);

                lret = g_utf8_strlen(in_path, PATH_MAX - 1);
                if (lret > (win_c - 2))
                    mvwprintw(win_text, 1, 1, "%s", g_utf8_offset_to_pointer(in_path, lret - win_c + 2));
                else
                    mvwprintw(win_text, 1, 1, "%s", in_path);
                wnoutrefresh(win_text);
            }
        }
        else if (ret == KEY_CODE_YES) {
            switch (in_char) {
                case KEY_BACKSPACE:
                    // delete the last character
                    *((char *)(g_utf8_offset_to_pointer(in_path, g_utf8_strlen(in_path, PATH_MAX) - 1))) = '\0';
                    --in_path_len;
                    werase(win_text);
                    box(win_text, 0, 0);
                    lret = g_utf8_strlen(in_path, PATH_MAX - 1);
                    if (lret > (win_c - 2))
                        mvwprintw(win_text, 1, 1, "%s", g_utf8_offset_to_pointer(in_path, lret - win_c + 2));
                    else
                        mvwprintw(win_text, 1, 1, "%s", in_path);
                    wnoutrefresh(win_text);
                    break;
                case KEY_DC:
                case KEY_LEFT:
                case KEY_RIGHT:
                    break;
                case KEY_UP:
                    if (win_origin_y > 0) {
                        --win_origin_y;
                        pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);
                    }
                    break;
                case KEY_DOWN:
                    if (win_origin_y + win_r <= entry_num + 5) {
                        ++win_origin_y;
                        pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);
                    }
                    break;
                case KEY_RESIZE:
                    // resize the window
                    wclear(win);
                    clear();
                    werase(win_frame);
                    werase(win_text);
                    wnoutrefresh(win_frame);
                    pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);
                    wnoutrefresh(win_text);
                    doupdate();
                    getmaxyx(stdscr, maxy, maxx);
                    win_c = maxx - 2;
                    win_r = maxy - 5; // we do -3 to make room for the text input

                    wresize(win, ((win_r > win_init_r) ? win_r : win_init_r),
                            (win_c > win_init_c) ? win_c : win_init_c);
                    wresize(win_frame, maxy, maxx);
                    wresize(win_text, 3, win_c);

                    mvwin(win_frame, 0, 0);
                    mvwin(win_text, maxy - 4, 1);
                    box(win_frame, 0, 0);
                    box(win_text, 0, 0);
                    wnoutrefresh(win_frame);
                    pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);

                    wmove(win_text, 1, 1);
                    wnoutrefresh(win_text);

                    x = 0;
                    y = 0;
                    mvwprintw(win, y, x, "Enter . to select the cwd, or a filename to select the respective file.");
                    ++y;
                    mvwprintw(win, y, x, "Use ESC (escape) to quit this dialog.");
                    ++y;
                    pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);

                    // print the cwd
                    cwd = g_get_current_dir();
                    if (cwd) {
                        mvwprintw(win, y, x, "Current directory: %s", cwd);
                        y += 2;
                        pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);

                        g_free(cwd);
                    }
                    cwd = NULL;

                    curr_dir = g_dir_open(".", 0, &err);
                    if (err) {
                        // TODO: check error codes, we don't want to print plain errors. error handle bbetter
                        log_warn("g_dir_open failed: %s | return -1", err->message);
                        g_clear_error(&err);
                        return -1;
                    }
                    // print the current directory

                    dir_entry = g_dir_read_name(curr_dir);
                    while (dir_entry) {
                        cpath = g_canonicalize_filename(dir_entry, NULL);
                        if (!cpath) {
                            g_chdir(initial_cwd);
                            g_free(initial_cwd);
                            g_dir_close(curr_dir);
                            delwin(win);
                            delwin(win_frame);
                            delwin(win_text);
                            log_error("g_canonicalize_filename() failed | return -1");
                            return -1;
                        }
                        ret = g_file_test(cpath, G_FILE_TEST_EXISTS);
                        if (ret == 0) {
                            g_free(cpath);
                            cpath = NULL;
                            continue;
                        }
                        ret = g_file_test(cpath, G_FILE_TEST_IS_DIR);
                        if (ret) {
                            // if it is a directory print it in blue
                            wattron(win, COLOR_PAIR(6) | A_BOLD);
                            mvwprintw(win, y, x, "%s", dir_entry);
                            wattroff(win, COLOR_PAIR(6) | A_BOLD);
                            ++y;
                        }
                        else {
                            // if it is a file or symlink print it in green
                            wattron(win, COLOR_PAIR(4) | A_BOLD);
                            mvwprintw(win, y, x, "%s", dir_entry);
                            wattroff(win, COLOR_PAIR(4) | A_BOLD);
                            ++y;
                        }
                        g_free(cpath);
                        cpath = NULL;
                        dir_entry = g_dir_read_name(curr_dir);
                    }
                    g_dir_close(curr_dir);
                    pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);
                    lret = g_utf8_strlen(in_path, PATH_MAX - 1);
                    if (ret > (win_c - 2))
                        mvwprintw(win_text, 1, 1, "%s", g_utf8_offset_to_pointer(in_path, lret - win_c + 2));
                    else
                        mvwprintw(win_text, 1, 1, "%s", in_path);
                    wnoutrefresh(win_text);
                    break;
                default:
                    break;
            }
        }
        else {
            break;
        }
        doupdate();
    }
    g_chdir(initial_cwd);
    g_free(initial_cwd);
    delwin(win);
    delwin(win_frame);
    delwin(win_text);
    log_error("wtf() failed | return -1");
    return -1;
}


int start_indigo_ui()
{

    return 0;
}