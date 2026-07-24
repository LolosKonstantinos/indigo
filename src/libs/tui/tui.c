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

#include "tui.h"
#include "Queue.h"
#include "binary_tree.h"
#include "crypto_utils.h"
#include "indigo_core/net_io.h"
#include "indigo_errors.h"
#include "indigo_types.h"
#include <config.h>
#include <glib-2.0/glib.h>
#include <glib-2.0/glib/gstdio.h>
//#include <ncursesw/curses.h>
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

#ifdef _WIN32
#define sleep(t) (Sleep(1000 * t))
#include <winsock2.h>
#endif

int verify_user(void **master_key)
{
    int ret = 0;

    if (!password_hash_exists()) {
        curs_set(0);
        if (!psw_salt_exists()) {
            ret = create_psw_salt(0);
            if (ret != INDIGO_SUCCESS) {
                curs_set(1);
                log_error("[verify_user] create_psw_salt() failed | return %d", ret);
                return ret;
            }
        }
        if (!key_derivation_settings_exist()) {
            int maxx;
            int maxy;
            getmaxyx(stdscr, maxy, maxx);
            move((maxy / 2) - 1, (maxx - 46) / 2);
            printw("Trying to set up password creation settings...");
            move((maxy / 2), (maxx - 45) / 2);
            printw("Testing for optimal settings for your system.");
            move((maxy / 2) + 1, (maxx - 31) / 2);
            printw("This might take several minutes");
            refresh();
            sleep(1);
            ret = create_key_derivation_settings();
            if (ret != INDIGO_SUCCESS) {
                curs_set(1);
                log_error("[verify_user] create_key_derivation_settings() failed | return %d", ret);
                return ret;
            }
            clear();
            refresh();
            getmaxyx(stdscr, maxy, maxx);
            move(maxy / 2, (maxx - 48) / 2);
            printw("Password creation settings created successfully.");
            refresh();
            sleep(3);
            clear();
        }
        curs_set(1);
        create_new_password();
    }
    ret = verify_password(master_key);
    if (ret) {
        log_error("[verify_user] verify_password() failed | return %d", ret);
        return ret;
    }
    if (!signing_key_pair_exists()) {
        ret = create_signing_key_pair(*master_key);
        if (ret)
            log_error("[verify_user] create_signing_key_pair() failed | return %d", ret);
    }
    return ret;
}

int verify_password(void **master_key)
{
    char *psw;
    wint_t ch;
    char mch;
    int overflow = 0;
    int ret = 0;
    int res = 0;
    char del = 0;
    char enter = 0;
    int psw_len = 0;
    WINDOW *password_window;
    char err_printed = 0;

    psw = sodium_malloc(MAX_PSW_LEN + 1);
    if (psw == NULL) {
        log_error("[verify_password] sodium_malloc() failed allocating %d bytes for plaintext password | return %d",
                  MAX_PSW_LEN + 1, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    sodium_memzero(psw, MAX_PSW_LEN + 1);

    password_window = create_welcome_screen();
    box(password_window, 0, 0);
    keypad(password_window, TRUE);
    wmove(password_window, 1, 1);
    refresh();
    wrefresh(password_window);

    while (1) {
        res = wget_wch(password_window, &ch);
        mch = (char)(ch & 0xff);
        if (res == KEY_CODE_YES) {
            switch (ch) {
                case KEY_BACKSPACE:
                    del = 1;
                    break;
                case KEY_ENTER:
                    enter = 1;
                    break;
                default:
                    break;
            }
        }
        else if (res == OK) {
            if (mch == '\n' || mch == '\r') {
                enter = 1;
            }
            else if (mch == '\b' || mch == 127) {
                del = 1;
            }
            else if (mch > 127 || !(iswalnum(mch) || iswspecialchar(mch))) {
                move(20, 0); // todo check this to be bellow the password window
                printw("[verify_password] use ONLY alpharithmetics and !@#$%%^&*_");
                refresh();
                wmove(password_window, 1, 1 + ((psw_len >= 62) ? 61 : psw_len));
                wrefresh(password_window);
            }
            else {
                if (psw_len < MAX_PSW_LEN) {
                    if (err_printed) {
                        wclear(password_window);
                        box(password_window, 0, 0);
                        wmove(password_window, 1, 1);
                        wrefresh(password_window);
                        err_printed = 0;
                    }
                    if (psw_len < 62)
                        wprintw(password_window, "*");
                    psw[psw_len] = mch;
                    psw_len++;
                }
                else {
                    overflow = 1;
                }
            }
        }
        else {
            sodium_memzero(psw, MAX_PSW_LEN);
            sodium_free(psw);
            delwin(password_window);
            log_error("[verify_password] wget_wch() returned error");
            return INDIGO_ERROR;
        }

        if (enter) {
            enter = 0;
            wclear(password_window);
            box(password_window, 0, 0);

            ret = cmp_password_hash(psw, psw_len);
            if (ret == 0) {
                break;
            }
            if (ret == 1 || overflow) {
                attron(COLOR_PAIR(1));
                mvwprintw(password_window, 1, 1, "PASSWORD INCORRECT. TRY AGAIN");
                attroff(COLOR_PAIR(1));
                wmove(password_window, 1, 1);
                wrefresh(password_window);
                err_printed = 1;
                overflow = 0;
                psw_len = 0;
                sodium_memzero(psw, MAX_PSW_LEN + 1);
            }
            else {
                sodium_free(psw);
                return -1;
            }
            wrefresh(password_window);
        }
        if (del) {
            del = 0;

            if (psw_len > 0) {
                psw_len--;
            }
            psw[psw_len] = '\0';
            wmove(password_window, 1, 1 + ((psw_len >= 62) ? 61 : psw_len));
            wprintw(password_window, " ");
            wmove(password_window, 1, 1 + ((psw_len >= 62) ? 61 : psw_len));
        }
    }
    // the password is verified, and we now derive the master key
    ret = derive_master_key(psw, psw_len, master_key);
    if (ret != 0 || !*master_key) {
        sodium_memzero(psw, MAX_PSW_LEN);
        sodium_free(psw);
        delwin(password_window);
        clear();
        refresh();
        log_error("[verify_password] derive_master_key() failed | return %d", ret);
        return ret;
    }

    sodium_memzero(psw, MAX_PSW_LEN);
    sodium_free(psw);
    delwin(password_window);
    clear();
    refresh();
    return 0;
}
WINDOW *create_welcome_screen()
{
    WINDOW *password_window;
    const int maxx = getmaxx(stdscr);
    password_window = newwin(3, 64, 17, (maxx - 64) / 2);
    mvprintw(0, (maxx - 64) / 2, " _       __________    __________  __  _________   __________   ");
    mvprintw(1, (maxx - 64) / 2, "| |     / / ____/ /   / ____/ __ \\/  |/  / ____/  /_  __/ __ \\");
    mvprintw(2, (maxx - 64) / 2, "| | /| / / __/ / /   / /   / / / / /|_/ / __/      / / / / / /  ");
    mvprintw(3, (maxx - 64) / 2, "| |/ |/ / /___/ /___/ /___/ /_/ / /  / / /___     / / / /_/ /   ");
    mvprintw(4, (maxx - 64) / 2, "|__/|__/_____/_____/\\____/\\____/_/__/_/_____/    /_/  \\____/ ");
    mvprintw(5, (maxx - 64) / 2, "              /  _/ | / / __ \\/  _/ ____/ __ \\                ");
    mvprintw(6, (maxx - 64) / 2, "              / //  |/ / / / // // / __/ / / /                  ");
    mvprintw(7, (maxx - 64) / 2, "            _/ // /|  / /_/ // // /_/ / /_/ /                   ");
    mvprintw(8, (maxx - 64) / 2, "           /___/_/ |_/_____/___/\\____/\\____/                  ");
    mvprintw(16, (maxx - 26) / 2, "PLEASE ENTER YOUR PASSWORD");

    return password_window;
}

int create_new_password()
{
    WINDOW *psw_win_1;
    WINDOW *psw_win_2;
    WINDOW *curr_window;
    char *psw_1;
    char *psw_2;
    int psw_len_1 = 0;
    int psw_len_2 = 0;
    wint_t ch;
    char mch;
    int res = 0;
    char enter = 0;
    char del = 0;
    char err_writen = 0;

    int maxx = getmaxx(stdscr);
    noecho();
    psw_1 = sodium_malloc(MAX_PSW_LEN + 1);
    if (!psw_1) {
        log_error("[create_new_password] sodium_malloc() failed allocating %d bytes for password plaintext | return %d",
                  MAX_PSW_LEN + 1, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    psw_2 = sodium_malloc(MAX_PSW_LEN + 1);
    if (!psw_2) {
        sodium_free(psw_1);
        log_error("[create_new_password] sodium_malloc() failed allocating %d bytes for password plaintext | return %d",
                  MAX_PSW_LEN + 1, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return 1;
    }
    sodium_memzero(psw_1, MAX_PSW_LEN + 1);
    sodium_memzero(psw_2, MAX_PSW_LEN + 1);
    psw_win_1 = newwin(3, 64, 16, (maxx - 64) / 2);
    psw_win_2 = newwin(3, 64, 22, (maxx - 64) / 2);
    box(psw_win_1, 0, 0);
    box(psw_win_2, 0, 0);
    // the welcome message
    {
        move(0, (maxx - 76) / 2);
        printw(" _    _ ______ _      _      ____    _______ _    _ ______ _____  ______    ");
        move(1, (maxx - 76) / 2);
        printw("| |  | |  ____| |    | |    / __ \\  |__   __| |  | |  ____|  __ \\|  ____| ");
        move(2, (maxx - 76) / 2);
        printw("| |__| | |__  | |    | |   | |  | |    | |  | |__| | |__  | |__) | |__      ");
        move(3, (maxx - 76) / 2);
        printw("|  __  |  __| | |    | |   | |  | |    | |  |  __  |  __| |  _  /|  __|     ");
        move(4, (maxx - 76) / 2);
        printw("| |  | | |____| |____| |___| |__| |    | |  | |  | | |____| | \\ \\| |____  ");
        move(5, (maxx - 76) / 2);
        printw("|_|  |_|______|______|______\\____/____ |_|_ |_|  |_|______|_|__\\_\\______|");
        move(6, (maxx - 76) / 2);
        printw("      | \\ | |  ____\\ \\        / / ____/ __ \\|  \\/  |  ____|  __ \\     ");
        move(7, (maxx - 76) / 2);
        printw("      |  \\| | |__   \\ \\  /\\  / / |   | |  | | \\  / | |__  | |__) |     ");
        move(8, (maxx - 76) / 2);
        printw("      | . ` |  __|   \\ \\/  \\/ /| |   | |  | | |\\/| |  __| |  _  /       ");
        move(9, (maxx - 76) / 2);
        printw("      | |\\  | |____   \\  /\\  / | |___| |__| | |  | | |____| | \\ \\      ");
        move(10, (maxx - 76) / 2);
        printw("      |_| \\_|______|   \\/  \\/   \\_____\\____/|_|  |_|______|_|  \\_\\   ");
    }
    move(12, (maxx - 25) / 2);
    printw("Your password is not set.");
    move(13, (maxx - 25) / 2);
    printw(" Let's create a new one!");
    move(15, 0);
    printw("Enter your password bellow (just type and hit enter when done): ");
    move(21, 0);
    printw("Re-enter your password to verify it.");
    keypad(psw_win_1, TRUE);
    keypad(psw_win_2, TRUE);
    curr_window = psw_win_1;

    refresh();
    wmove(psw_win_1, 1, 1);
    wrefresh(psw_win_1);
    wrefresh(psw_win_2);
    wmove(psw_win_1, 1, 1);
    while (1) {
        res = wget_wch(curr_window, &ch);
        mch = (char)(ch & 0xff);
        if (res == KEY_CODE_YES) {
            switch (ch) {
                case KEY_UP:
                    wmove(psw_win_1, 1, 1 + ((psw_len_1 > 62) ? 60 : psw_len_1));
                    curr_window = psw_win_1;
                    break;
                case KEY_DOWN:
                    wmove(psw_win_2, 1, 1 + ((psw_len_2 > 62) ? 60 : psw_len_2));
                    curr_window = psw_win_2;
                    break;
                case KEY_BACKSPACE:
                    del = 1;
                    break;
                case KEY_ENTER:
                    enter = 1;
                    break;
                default:
                    break;
            }
        }
        else if (res == OK) {
            if (ch == '\n' || ch == '\r') {
                enter = 1;
            }
            else if (ch == '\b' || ch == 127) {
                del = 1;
            }
            else if (ch > 127 || !(iswalnum(ch) || iswspecialchar(ch))) {
                move(19, 0);
                printw("use ONLY alpharithmetics and !@#$%%^&*_");
                refresh();

                if (curr_window == psw_win_1) {
                    wmove(psw_win_1, 1, 1 + ((psw_len_1 > 62) ? 61 : psw_len_1));
                    wrefresh(psw_win_1);
                }
                else {
                    wmove(psw_win_2, 1, 1 + ((psw_len_2 > 62) ? 61 : psw_len_2));
                    wrefresh(psw_win_2);
                }
            }
            else {
                if (curr_window == psw_win_1) {
                    if (psw_len_1 < MAX_PSW_LEN) {
                        if (err_writen) {
                            wclear(psw_win_1);
                            box(psw_win_1, 0, 0);
                            wrefresh(psw_win_1);
                            wmove(psw_win_1, 1, 1);
                            err_writen = 0;
                        }
                        if (psw_len_1 < 62) {
                            wprintw(curr_window, "*");
                        }
                        psw_1[psw_len_1] = mch;
                        psw_len_1++;
                    }
                }
                else {
                    if (psw_len_2 < MAX_PSW_LEN) {
                        if (psw_len_2 < 62) {
                            wprintw(curr_window, "*");
                        }
                        psw_2[psw_len_2] = mch;
                        psw_len_2++;
                    }
                }
            }
        }
        else {
            sodium_memzero(psw_1, MAX_PSW_LEN);
            sodium_memzero(psw_2, MAX_PSW_LEN);
            sodium_free(psw_1);
            sodium_free(psw_2);
            delwin(psw_win_1);
            delwin(psw_win_2);
            return INDIGO_ERROR;
        }

        if (enter) {
            enter = 0;
            if (curr_window == psw_win_1) {
                wmove(psw_win_2, 1, 1 + ((psw_len_2 > 62) ? 60 : psw_len_2));
                curr_window = psw_win_2;
                continue;
            }
            if (psw_len_1 != psw_len_2) {
                wclear(psw_win_1);
                wclear(psw_win_2);
                box(psw_win_1, 0, 0);
                box(psw_win_2, 0, 0);
                psw_len_1 = psw_len_2 = 0;
                sodium_memzero(psw_1, MAX_PSW_LEN);
                sodium_memzero(psw_2, MAX_PSW_LEN);
                wmove(psw_win_1, 1, 1);
                wprintw(psw_win_1, "passwords are not the same, please try again!");
                wrefresh(psw_win_1);
                wrefresh(psw_win_2);
                err_writen = 1;
                curr_window = psw_win_1;
                continue;
            }
            if (sodium_memcmp(psw_1, psw_2, MAX_PSW_LEN) == 0) {
                break;
            }

            wclear(psw_win_1);
            wclear(psw_win_2);
            box(psw_win_1, 0, 0);
            box(psw_win_2, 0, 0);
            psw_len_1 = psw_len_2 = 0;
            sodium_memzero(psw_1, MAX_PSW_LEN);
            sodium_memzero(psw_2, MAX_PSW_LEN);
            wmove(psw_win_1, 1, 1);
            wprintw(psw_win_1, "passwords are not the same, please try again!");
            wrefresh(psw_win_1);
            wrefresh(psw_win_2);
            err_writen = 1;
            curr_window = psw_win_1;
            continue;
        }
        if (del) {
            del = 0;
            if (curr_window == psw_win_1) {
                if (psw_len_1 > 0) {
                    psw_len_1--;
                }
                psw_1[psw_len_1] = '\0';
                wmove(psw_win_1, 1, 1 + ((psw_len_1 >= 62) ? 61 : psw_len_1));
                wprintw(psw_win_1, " ");
                wmove(psw_win_1, 1, 1 + ((psw_len_1 >= 62) ? 61 : psw_len_1));
            }
            else {
                if (psw_len_2 > 0) {
                    psw_len_2--;
                }
                psw_2[psw_len_2] = '\0';
                wmove(psw_win_2, 1, 1 + ((psw_len_2 >= 62) ? 61 : psw_len_2));
                wprintw(psw_win_2, " ");
                wmove(psw_win_2, 1, 1 + ((psw_len_2 >= 62) ? 61 : psw_len_2));
            }
        }
    }
    res = save_password_hash(psw_1, psw_len_1);
    if (res != INDIGO_SUCCESS) {
        sodium_memzero(psw_1, MAX_PSW_LEN);
        sodium_memzero(psw_2, MAX_PSW_LEN);
        sodium_free(psw_1);
        sodium_free(psw_2);
        delwin(psw_win_1);
        delwin(psw_win_2);
        log_error("[create_new_password] save_password_hash() failed | return %d", res);
        return res;
    }
    sodium_memzero(psw_1, MAX_PSW_LEN);
    sodium_memzero(psw_2, MAX_PSW_LEN);
    sodium_free(psw_1);
    sodium_free(psw_2);
    delwin(psw_win_1);
    delwin(psw_win_2);
    clear();
    refresh();
    return 0;
}
int iswspecialchar(const wint_t ch)
{
    switch (ch) {
        case '!':
        case '@':
        case '#':
        case '$':
        case '%':
        case '^':
        case '&':
        case '*':
        case '_':
            return 1;
        default:
            return 0;
    }
}

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

int create_main_interface(tree_t *dev_tree, tree_t *file_tree, QUEUE *ui_queue, QUEUE *ph_queue, QUEUE *send_queue)
{
    tree_iterator_t *dev_iter;
    WINDOW *device_pad;

    int maxx;
    int maxy;
    int win_r;
    int win_c;

    int device_top_row = 0;
    int file_top_row = 0;

    utf8_char_t ch;
    char context = 0; // 0 is for devises and 1 is for devide info

    Q_SEND_FILE *send_node;
    Q_FILE_SENDING_REQUEST *fsr = NULL;

    remote_device_t rdev;
    remote_device_t *rdev_p = NULL;

    unsigned char **dev_IDs = NULL;
    size_t id_count = 0;
    unsigned char last_id[crypto_sign_PUBLICKEYBYTES] = {0};
    int last_id_row = 0;

    char selected_path[PATH_MAX];

    unsigned char **request_list = NULL;
    int request_count = 0;
    unsigned char **file_list = NULL;
    int file_count = 0;

    int file_last_row = 0;
    char file_last_level = 0;

    tree_t *known_key_tree;
    uint64_t status = 0;

    int ret;

    if (!dev_tree || !file_tree || !ui_queue || !ph_queue || !send_queue) {
        log_error("[create_main_interface] null parameter(s) | return %d", INDIGO_ERROR_INVALID_PARAM);
        return INDIGO_ERROR_INVALID_PARAM;
    }

    ret = new_tree(&known_key_tree, key_cmp, sizeof(known_key_t), BINARY_TREE_FLAG_AVL);
    if (ret) {
        log_error("[create_main_interface] new_tree() for known_keys failed | return %d", ret);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    ret = load_known_keys(known_key_tree);
    if (ret != INDIGO_SUCCESS && ret != INDIGO_ERROR_FILE_NOT_FOUND) {
        free_tree(known_key_tree);
        log_error("[create_main_interface] load_known_keys() failed | return %d", ret);
        return ret;
    }

    memset(last_id, 0, crypto_sign_PUBLICKEYBYTES);

    getmaxyx(stdscr, maxy, maxx);
    win_r = (100 > maxy) ? 100 : maxy;
    win_c = (100 > maxx) ? 100 : maxx;
    device_pad = newpad(win_r, win_c);

    keypad(device_pad, TRUE);
    curs_set(0);
    halfdelay(10);

    pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy - 1, maxx - 1);

    // the main loop
    while (1) {
        ret = get_user_input(device_pad, &ch);
        if (ret == KEY_CODE_YES) {
            // function keys
            switch (ch) {
                case KEY_DOWN:
                    if (context == 0) {
                        if (last_id_row < id_count - 1) {
                            wchgat(device_pad, 3, A_NORMAL, 0, NULL);
                            wmove(device_pad, ++last_id_row, 0);
                            wchgat(device_pad, 3, A_REVERSE, 0, NULL);
                            memcpy(last_id, dev_IDs[last_id_row], crypto_sign_PUBLICKEYBYTES);
                            if (device_top_row + win_c <= id_count) {
                                ++device_top_row;
                            }
                            pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy - 1, maxx - 1);
                        }
                    }
                    else {
                        if (file_last_level == 0) {
                            if (file_last_row < 3) {
                                wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                ++file_last_row;
                                wmove(device_pad, 4 + file_last_row, 0);
                                wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                            }
                            else {
                                if (request_count > 0) {
                                    wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                    file_last_level = 1;
                                    file_last_row = 0;
                                    wmove(device_pad, 10, 0);
                                    wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                                }
                                else if (file_count > 0) {
                                    wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                    file_last_level = 2;
                                    file_last_row = 0;
                                    wmove(device_pad, 9 + request_count + 3, 0);
                                    wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                                }
                            }
                        }
                        else if (file_last_level == 1) {
                            if (file_last_row < request_count - 1) {
                                wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                ++file_last_row;
                                wmove(device_pad, 9 + file_last_row, 0);
                                wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                            }
                            else if (file_count > 0) {
                                wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                file_last_level = 2;
                                file_last_row = 0;
                                wmove(device_pad, 9 + request_count + 3, 0);
                                wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                            }
                        }
                        else {
                            if (file_last_row < file_count - 1) {
                                wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                ++file_last_row;
                                wmove(device_pad, 9 + request_count + 3 + file_last_row, 0);
                                wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                            }
                        }
                        if (file_top_row + win_c <= 8 + 1 + request_count + 1 + file_count) {
                            ++file_top_row;
                        }
                        pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy - 1, maxx - 1);
                    }
                    break;
                case KEY_UP:
                    if (context == 0) {
                        if (last_id_row > 0) {
                            wchgat(device_pad, 3, A_NORMAL, 0, NULL);
                            wmove(device_pad, --last_id_row, 0);
                            wchgat(device_pad, 3, A_REVERSE, 0, NULL);
                            if (device_top_row > 0) {
                                --device_top_row;
                            }
                            pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy - 1, maxx - 1);
                        }
                    }
                    else if (context == 1) {
                        if (file_last_level == 0) {
                            if (file_last_row > 0) {
                                wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                --file_last_row;
                                wmove(device_pad, 4 + file_last_row, 0);
                                wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                            }
                        }
                        else if (file_last_level == 1) {
                            if (file_last_row > 0) {
                                wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                --file_last_row;
                                wmove(device_pad, 9 + file_last_row, 0);
                                wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                            }
                            else if (file_count == 0) {
                                wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                file_last_level = 0;
                                file_last_row = 3;
                                wmove(device_pad, 4 + file_last_row, 0);
                                wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                            }
                        }
                        else {
                            if (file_last_row > 0) {
                                wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                --file_last_row;
                                wmove(device_pad, 9 + request_count + 3 + file_last_row, 0);
                                wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                            }
                            else if (file_count == 0) {
                                if (request_count > 0) {
                                    wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                    file_last_level = 1;
                                    file_last_row = request_count - 1;
                                    wmove(device_pad, 9 + file_last_row, 0);
                                    wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                                }
                                else {
                                    wchgat(device_pad, -1, A_NORMAL, 0, NULL);
                                    file_last_level = 0;
                                    file_last_row = 3;
                                    wmove(device_pad, 4 + file_last_row, 0);
                                    wchgat(device_pad, -1, A_REVERSE, 0, NULL);
                                }
                            }
                        }
                    }
                    break;
                case KEY_LEFT:
                case KEY_RIGHT:
                case KEY_DC: // delete
                case KEY_RESIZE:
                default:
                    break;
            }
        }
        else if (ret == OK) {
            // characters
            if (ch == '\x1b')
                break;
            if (ch == '\n' || ch == '\r') {
                // select the action
                if (context == 0) {
                    if (id_count > 0)
                        context = 1;
                    print_device_files(device_pad, last_id, dev_tree, file_tree, &request_list, &request_count,
                                       &file_list, &file_count, &file_last_row, &file_last_level);
                    doupdate();
                    continue;
                }
                if (file_last_level == 0) {
                    if (file_last_row == 0) {
                        // send a file
                        ret = pathfinder(selected_path);
                        if (ret == -1) {
                            // it is probably a memory error
                            //  TODO: handle all errors
                            log_error("pathfinder() failed | return -1");
                            goto cleanup;
                        }
                        if (ret == 1)
                            continue;
                        if (ret == 0) {
                            // send this to the queue
                            send_node = malloc(sizeof(Q_SEND_FILE));
                            if (!send_node) {
                                ret = INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
                                log_error("malloc() failed allocating %d bytes for queue node data Q_SENd_FILE "
                                          "| return %d",
                                          sizeof(Q_SEND_FILE), ret);
                                goto cleanup;
                            }

                            memcpy(rdev.peer_pk, last_id, crypto_sign_PUBLICKEYBYTES);

                            ret = dev_tree->search_pin(dev_tree, &rdev, (void **)&rdev_p);
                            if (ret == 1) {
                                send_node->ip = rdev_p->ip;
                                send_node->tk = rdev_p->client_tk;
                                send_node->session_id.serial = ++(rdev_p->last_fid);
                            }
                            dev_tree->search_release(dev_tree);

                            send_node->counter = 0;
                            send_node->port = PORT;
                            send_node->next = NULL;
                            memcpy(send_node->session_id.pk, last_id, crypto_sign_PUBLICKEYBYTES);
                            randombytes(send_node->nonce, 24);

                            ret = queue_push(send_queue, send_node, QET_SEND_FILE);
                            if (ret) {
                                free(send_node);
                                send_node = NULL;
                                log_error("queue_push() failed | return %d", ret);
                                goto cleanup;
                            }
                            send_node = NULL;
                        }
                    }
                    else {
                        // set the trust status
                        switch (file_last_row) {
                            case 1:
                                status = KNOWN_KEY_STATUS_TOO_GOOD;
                                break;
                            case 2:
                                status = KNOWN_KEY_STATUS_GOOD;
                                break;
                            case 3:
                                status = KNOWN_KEY_STATUS_BAD;
                                break;
                            default:
                                status = KNOWN_KEY_STATUS_UNKNOWN;
                                break;
                        }
                        edit_known_key(known_key_tree, last_id, status);
                    }
                }
                // TODO: HUGE TODO
                else if (file_last_level == 1) {
                }
            }
            else if (ch == ' ' && context == 1 && file_last_level == 2) {
                // pause files
            }
        }

        // update the ui
        if (context == 0) {
            if (dev_IDs != NULL) {
                for (int i = 0; i < id_count; ++i) {
                    free(dev_IDs[i]);
                }
                free(dev_IDs);
                dev_IDs = NULL;
            }
            werase(device_pad);
            print_devices(device_pad, dev_tree, &dev_IDs, &id_count, last_id, &last_id_row);

            if (id_count == 0) {
                mvwprintw(device_pad, 0, 0, "There are currently no devices in the local network.");
            }
            pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy - 1, maxx - 1);
        }
        else {
            if (request_list != NULL) {
                for (int i = 0; i < request_count; ++i) {
                    free(request_list[i]);
                }
                free(request_list);
                request_list = NULL;
            }

            if (file_list != NULL) {
                for (int i = 0; i < file_count; ++i) {
                    free(file_list[i]);
                }
                free(file_list);
                file_list = NULL;
            }

            werase(device_pad);
            print_device_files(device_pad, last_id, dev_tree, file_tree, &request_list, &request_count, &file_list,
                               &file_count, &file_last_row, &file_last_level);
            pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy - 1, maxx - 1);
        }
        doupdate();
    }

    free_tree(known_key_tree);
    delwin(device_pad);
    return 0;

cleanup:
    if (dev_IDs != NULL) {
        for (int i = 0; i < id_count; ++i) {
            free(dev_IDs[i]);
        }
        free(dev_IDs);
    }
    if (file_list != NULL) {
        for (int i = 0; i < file_count; ++i) {
            free(file_list[i]);
        }
        free(file_list);
    }
    if (request_list != NULL) {
        for (int i = 0; i < request_count; ++i) {
            free(request_list[i]);
        }
        free(request_list);
    }
    free_tree(known_key_tree);
    delwin(device_pad);
    return ret;
}

int pathfinder(char path[PATH_MAX])
{
    utf8_char_t in_char;
    int key_repeat_count = 0;
    uint64_t character_len = 0;
    char in_path[PATH_MAX] = {0};
    char *initial_cwd = NULL;
    int in_path_len = 0;
    int ret = 0;
    int64_t lret = 0;
    GDir *curr_dir = NULL;
    GError *err = NULL;
    GStatBuf stat_buf;
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
    int longest_path = 0;
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
    return -1;
}

int print_devices(WINDOW *win, tree_t *dev_tree, unsigned char ***dev_IDs, size_t *id_count,
                  unsigned char last_id[crypto_sign_PUBLICKEYBYTES], int *last_row)
{
    int ret;
    int count = 0;
    tree_iterator_t *iter;
    remote_device_t *rdev = NULL;
    remote_device_t *found_rdev = NULL;
    remote_device_t s_rdev;
    known_key_t known_key;
    unsigned char **id_array = NULL;
    char highlight = 0;
    char found = 0;
    void *temp = NULL;

    if (!dev_IDs || !dev_tree || !win || !last_id || !last_row) {
        log_error("null argument(s) | return -1");
        return -1;
    }

    memcpy(s_rdev.peer_pk, last_id, crypto_sign_PUBLICKEYBYTES);
    // searches the tree and does not unlock it
    found = (char)dev_tree->search_pin(dev_tree, &s_rdev, (void **)&found_rdev);

    ret = new_tree_iterator(dev_tree, &iter);
    while (tree_has_next(iter)) {
        if (found && (memcmp(last_id, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES) == 0)) {
            // ignore the device that was last highlighted
            // it will be printed on the same line it was before
            continue;
        }
        if (count == *last_row && found) {
            // print the last highlighted device on the row it was before
            print_device(win, found_rdev, count, 1);
            ++count;
            // add the device to the id array
            temp = realloc(id_array, count * sizeof(unsigned char *));
            if (!temp) {
                tree_unlock(dev_tree);
                log_error("realloc() failed re-allocating %d bytes for id array | return -1",
                          count * sizeof(unsigned char));
                return -1;
            }
            id_array = temp;
            temp = malloc(crypto_sign_PUBLICKEYBYTES);
            if (!temp) {
                tree_unlock(dev_tree);
                log_error("malloc() failed allocating %d bytes for device id | return -1", crypto_sign_PUBLICKEYBYTES);
                return -1;
            }
            id_array[count - 1] = temp;
            memcpy(temp, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
            continue;
        }
        else if (count == *last_row && found == 0)
            highlight = 1;

        tree_next(iter, (void **)&rdev);

        print_device(win, rdev, count, highlight);
        ++count;

        highlight = 0;

        // add the device to the id array
        temp = realloc(id_array, count * sizeof(unsigned char *));
        if (!temp) {
            free_tree_iterator(&iter);
            tree_unlock(dev_tree);
            log_error("realloc() failed re-allocating %d bytes for id array | return -1",
                      count * sizeof(unsigned char));
            return -1;
        }
        id_array = temp;
        temp = malloc(crypto_sign_PUBLICKEYBYTES);
        if (!temp) {
            free_tree_iterator(&iter);
            id_array[count - 1] = NULL;
            tree_unlock(dev_tree);
            log_error("malloc() failed allocating %d bytes for device id | return -1", crypto_sign_PUBLICKEYBYTES);
            return -1;
        }
        id_array[count - 1] = temp;
        memcpy(temp, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
        *dev_IDs = id_array;
        *id_count = count;
    }
    if (found && count < *last_row) {
        // some devises got removed, so we print our device at the end
        print_device(win, found_rdev, count, 1);
        ++count;
        *last_row = count;

        // add the device to the id array
        temp = realloc(id_array, count * sizeof(unsigned char *));
        if (!temp) {
            free_tree_iterator(&iter);
            tree_unlock(dev_tree);
            log_error("realloc() failed re-allocating %d bytes for id array | return -1",
                      count * sizeof(unsigned char));
            return -1;
        }
        id_array = temp;
        temp = malloc(crypto_sign_PUBLICKEYBYTES);
        if (!temp) {
            free_tree_iterator(&iter);
            tree_unlock(dev_tree);
            log_error("malloc() failed allocating %d bytes for device id | return -1", crypto_sign_PUBLICKEYBYTES);
            return -1;
        }
        id_array[count - 1] = temp;
        memcpy(temp, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
    }
    else if (!found && count < *last_row) {
        // if we haven't highlighted any device yet, we highlight the last one
        // that is because we have less devises than before and the last one is not there
        // so the lowest device above the last device is the last one printed
        wmove(win, count, 0);
        wchgat(win, 3, A_REVERSE, 0, NULL);
        *last_row = count;
        memcpy(last_id, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
    }
    free_tree_iterator(&iter);
    tree_unlock(dev_tree);

    *id_count = count;
    *dev_IDs = id_array;

    return 0;
}

int print_device(WINDOW *win, remote_device_t *rdev, int row, char highlight)
{
    uint8_t *ip_bytes;
    known_key_t known_key;
    if (!win || !rdev)
        return -1;

    wmove(win, row, 0);
    wprintw(win, "dev%u ", row);
    wattron(win, COLOR_PAIR(5));
    wprintw(win, "%s ", rdev->username);
    wattroff(win, COLOR_PAIR(5));
    ip_bytes = (uint8_t *)&(rdev->ip);
    wattron(win, COLOR_PAIR(2));
    wprintw(win, "%d.%d.%d.%d ", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    wattroff(win, COLOR_PAIR(2));
    memcpy(known_key.key, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
    if (rdev->dev_state_flag & KNOWN_KEY_STATUS_TOO_GOOD) {
        wattron(win, COLOR_PAIR(4) | A_BOLD);
        wprintw(win, "[TRUSTED+]");
        wattroff(win, COLOR_PAIR(4) | A_BOLD);
    }
    else if (rdev->dev_state_flag & KNOWN_KEY_STATUS_GOOD) {
        wattron(win, COLOR_PAIR(4));
        wprintw(win, "[TRUSTED]");
        wattroff(win, COLOR_PAIR(4));
    }
    else if (rdev->dev_state_flag & KNOWN_KEY_STATUS_UNKNOWN) {
        wattron(win, COLOR_PAIR(3));
        wprintw(win, "[UNKNOWN]");
        wattroff(win, COLOR_PAIR(3));
    }
    else if (rdev->dev_state_flag & KNOWN_KEY_STATUS_BAD) {
        wattron(win, COLOR_PAIR(1));
        wprintw(win, "[DANGEROUS]");
        wattroff(win, COLOR_PAIR(1));
    }
    else if (rdev->dev_state_flag & KNOWN_KEY_STATUS_EVIL_AND_SINISTER) {
        wattron(win, COLOR_PAIR(1) | A_BOLD);
        wprintw(win, "[SINISTER]");
        wattroff(win, COLOR_PAIR(1) | A_BOLD);
    }
    if (rdev->fsr_count > 0) {
        wattron(win, COLOR_PAIR(3));
        wprintw(win, " (%d)", rdev->fsr_count);
        wattroff(win, COLOR_PAIR(3));
    }

    if (highlight) {
        wmove(win, row, 0);
        wchgat(win, 3, A_REVERSE, 0, NULL);
    }
    return 0;
}

int print_device_files(WINDOW *win, unsigned char id[32], tree_t *dev_tree, tree_t *active_files,
                       unsigned char ***requests_list, int *request_count, unsigned char ***file_list, int *file_count,
                       int *last_row, char *level)
{
    int ret;
    void *temp;
    int temp_row = 0;
    int count = 0;
    int y = 0;
    int i;
    size_t file_size;
    char *username;
    char *file_name;
    const char *const units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    const char *const directions[] = {"UP", "DOWN"};
    remote_device_t rdev;
    remote_device_t *found_rdev;
    tree_iterator_t *iter;
    ui_file_t *file;

    if (!win || !dev_tree || !active_files || !requests_list || !file_list || !request_count || !file_count ||
        !last_row || !level) {
        return -1;
    }

    memcpy(rdev.peer_pk, id, crypto_sign_PUBLICKEYBYTES);
    ret = dev_tree->search_pin(dev_tree, &rdev, (void **)&found_rdev);
    if (ret == 0) {
        // the device was not found
        // we return with an error
        tree_unlock(dev_tree);
        log_warn("device not found | return 1");
        return 1;
    }

    username = g_utf8_make_valid(rdev.username, MAX_USERNAME_LEN * sizeof(uint32_t));
    if (!username) {
        tree_unlock(dev_tree);
        log_error("g_utf8_make_valid() failed");
        return -1;
    }
    if (g_utf8_strlen(username, -1) > MAX_USERNAME_LEN) {
        *(g_utf8_offset_to_pointer(username, MAX_USERNAME_LEN)) = '\0';
    }

    wmove(win, 0, 0);

    wprintw(win, "%s", username);
    g_free(username);
    wmove(win, ++y, 0);
    for (i = 0; i < 32; ++i) {
        wprintw(win, "%02x", id[i]);
    }

    wmove(win, ++y, 0);
    mvwprintw(win, ++y, 0, "[actions]");
    mvwprintw(win, ++y, 0, ">send a file...");
    temp_row = y;
    mvwprintw(win, ++y, 0, ">trust this device.");
    mvwprintw(win, ++y, 0, ">super trust this device.");
    mvwprintw(win, ++y, 0, ">device is EVIL and SINISTER.");

    if (*level == 0) {
        if (*last_row > y) {
            *last_row = 0;
        }
        wmove(win, temp_row + *last_row, 0);
        wchgat(win, -1, A_REVERSE, 0, NULL);
    }

    wmove(win, ++y, 0);
    mvwprintw(win, ++y, 0, "[requests]");
    temp_row = y;
    for (fwd_fsr_t *fsr = found_rdev->fsr_list; fsr != NULL; fsr = fsr->next) {
        file_name = g_utf8_make_valid(fsr->file_name, NAME_MAX);
        if (!username) {
            tree_unlock(dev_tree);
            return -1;
        }
        mvwprintw(win, ++y, 0, "%s ", file_name);

        file_size = fsr->file_size;
        for (i = 0; i < 7; ++i) {
            if (file_size >> 10 != 0)
                file_size >>= 10;
            else
                break;
        }
        file_size = fsr->file_size;
        wprintw(win, "%.2f %s", (float)file_size / (float)((unsigned long long)1 << (i * 10)), units[i]);
        g_free(file_name);

        // add the device to the id array
        ++count;
        temp = realloc(requests_list, count * sizeof(unsigned char *));
        if (!temp) {
            tree_unlock(dev_tree);
            for (i = 0; i < count - 1; ++i) {
                free(requests_list[i]);
            }
            free(requests_list);
            *requests_list = NULL;
            *file_list = NULL;
            *request_count = 0;
            *file_count = 0;
            log_error("realloc() failed allocating %lld bytes for request list | return -1",
                      count * sizeof(unsigned char));
            return -1;
        }
        requests_list = temp;
        temp = malloc(crypto_sign_PUBLICKEYBYTES);
        if (!temp) {
            tree_unlock(dev_tree);
            for (int j = 0; j < count - 1; ++j) {
                free(requests_list[j]);
            }
            free(requests_list);
            *requests_list = NULL;
            *file_list = NULL;
            *request_count = 0;
            *file_count = 0;
            log_error("malloc failed allocating %d bytes for device id | return -1", crypto_sign_PUBLICKEYBYTES);
            return -1;
        }
        requests_list[count] = temp;
        memcpy(temp, fsr->id, crypto_sign_PUBLICKEYBYTES);
    }
    tree_unlock(dev_tree);
    *request_count = count;

    if (*level == 1) {
        if (count > 0 && *last_row > count - 1) {
            *last_row = count - 1;
        }
        else if (count == 0) {
            *last_row = 0;
            *level = 0;
            temp_row = 4; // it is the y for the send file
        }
        wmove(win, temp_row + count, 0);
        wchgat(win, -1, A_REVERSE, 0, NULL);
    }
    count = 0;

    wmove(win, ++y, 0);
    mvwprintw(win, ++y, 0, "[active files]");
    temp_row = y;

    tree_lock(active_files);
    new_tree_iterator(active_files, &iter);
    while (tree_has_next(iter)) {
        tree_next(iter, (void **)&file);
        if (memcmp(id, file->id.pk, crypto_sign_PUBLICKEYBYTES) == 0) {
            mvwprintw(win, ++y, 0, "%s [%s]", file->name, directions[file->direction]);
            // add the device to the id array
            ++count;
            temp = realloc(file_list, count * sizeof(unsigned char *));
            if (!temp) {
                free_tree_iterator(&iter);
                tree_unlock(active_files);
                for (int j = 0; j < count - 1; ++j) {
                    free(file_list[j]);
                }
                free(file_list);
                *file_list = NULL;
                *file_count = 0;
                log_error("realloc() failed allocating %lld bytes for request list | return -1",
                          count * sizeof(unsigned char));
                return -1;
            }
            file_list = temp;
            temp = malloc(crypto_sign_PUBLICKEYBYTES);
            if (!temp) {
                free_tree_iterator(&iter);
                tree_unlock(active_files);
                for (int j = 0; j < count - 1; ++j) {
                    free(file_list[j]);
                }
                free(file_list);
                *file_list = NULL;
                *file_count = 0;
                log_error("malloc failed allocating %d bytes for device id | return -1", crypto_sign_PUBLICKEYBYTES);
                return -1;
            }
            file_list[count - 1] = temp;
            memcpy(temp, file->id.pk, crypto_sign_PUBLICKEYBYTES);
        }
    }
    free_tree_iterator(&iter);
    tree_unlock(active_files);
    *file_count = count;
    if (*level == 2) {
        if (count > 0 && *last_row > count - 1) {
            *last_row = count - 1;
        }
        else if (count == 0) {
            *last_row = 0;
            *level = 0;
            temp_row = 4; // it is the y for the send file
        }
        wmove(win, temp_row + count, 0);
        wchgat(win, -1, A_REVERSE, 0, NULL);
    }

    return 0;
}
