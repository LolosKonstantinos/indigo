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
#include "indigo_errors.h"
#include "indigo_types.h"
#include "lht.h"
#include <config.h>
#include <glib-2.0/glib.h>
#include <glib-2.0/glib/gstdio.h>
#include <linux/limits.h>
#include <ncursesw/curses.h>
#include <pthread.h>
#include <sodium/crypto_sign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wctype.h>
#ifdef _WIN32
#define sleep(t) (Sleep(1000 * t))
#endif
int verify_user(void **master_key)
{
    int ret = 0;

    if (!password_hash_exists()) {
        curs_set(0);
        if (!psw_salt_exists()) {
            ret = create_psw_salt(0);
            if (ret != INDIGO_SUCCESS) {
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
        fprintf(stderr, "error in verify_password() called inside verify_user");
        return ret;
    }

    if (!signing_key_pair_exists()) {
        ret = create_signing_key_pair(*master_key);
        printf("did not crash %p", *master_key);
    }
    return ret;
}
// todo this function makes the process crash, probably segfault, does not verify password correctly in debug mode
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
        fprintf(stderr, "\nerror:memory allocation failed.\n");
        return -1;
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
                printw("use ONLY alpharithmetics and !@#$%%^&*_");
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
        printf("derive master key return: %d\n", ret);
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
        return 1;
    }
    psw_2 = sodium_malloc(MAX_PSW_LEN + 1);
    if (!psw_2) {
        sodium_free(psw_1);
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
        ret = c16rtomb(*input, c, &state);
        switch (ret) {
            case ((size_t)(-1)):
                return -1;
            case 0:
                ret = wget_wch(win, &c);
                if (ret == OK) {
                    ret = c16rtomb(*input, c, &state);
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
        wctomb((char *)input, c);
        return OK;
    }
    else if (ret == KEY_CODE_YES) {
        *input = c;
        return KEY_CODE_YES;
    }
    return -1;
#endif
}

// TODO: so as to not forget it
//       user name is cyan
//       ip is magenta
//       trusted is [TRUSTED] and green
//       not trusted yet is [UNKOWN] and yellow
//       blocked or dagerous is [DANGEROUS] and red
int create_main_interface(tree_t *dev_tree, QUEUE *ui_queue, QUEUE *ph_queue)
{
    tree_iterator_t *dev_iter;
    WINDOW *notification_win;
    WINDOW *device_pad;
    // WINDOW *devinfo_pad;
    // WINDOW *text_input_win;

    int maxx;
    int maxy;
    int win_r;
    int win_c;

    int device_top_row = 0;

    utf8_char_t ch;
    char context = 0; // 0 is for devises and 1 is for devide info

    QNODE *qnode = NULL;
    Q_FILE_SENDING_REQUEST *fsr = NULL;

    remote_device_t rdev;
    remote_device_t *rdev_p = NULL;

    unsigned char **dev_IDs = NULL;
    size_t id_count = 0;
    unsigned char last_id[crypto_sign_PUBLICKEYBYTES];
    int last_id_row = 0;

    char selected_path[PATH_MAX];

    int ret;

    memset(last_id, 0, crypto_sign_PUBLICKEYBYTES);

    getmaxyx(stdscr, maxy, maxx);
    win_r = (100 > maxy) ? 100 : maxy;
    win_c = (100 > maxx) ? 100 : maxx;
    device_pad = newpad(win_r, win_c);

    keypad(device_pad, TRUE);
    curs_set(0);
    halfdelay(10);

    pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy, maxx);
    // pnoutrefresh(devinfo_pad, devinfo_top_row, 0, 3, 0, maxy - 5, maxx - (int)(maxx * 0.3));

    // wnoutrefresh(text_input_win);

    // the main loop
    while (1) {
        ret = get_user_input(device_pad, &ch);
        if (ret == KEY_CODE_YES) {
            // function keys
            switch (ch) {
                case KEY_DOWN:
                    if (context == 0) {
                        if (device_top_row + win_c <= id_count) {
                            wchgat(device_pad, 3, A_NORMAL, 0, NULL);
                            wmove(device_pad, ++device_top_row, 0);
                            wchgat(device_pad, 3, A_REVERSE, 0, NULL);
                            ++last_id_row;
                            pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy, maxx);
                        }
                    }
                    else {
                    }
                    break;
                case KEY_UP:
                    if (context == 0) {
                        if (device_top_row > 0) {
                            wchgat(device_pad, 3, A_NORMAL, 0, NULL);
                            wmove(device_pad, --device_top_row, 0);
                            wchgat(device_pad, 3, A_REVERSE, 0, NULL);
                            --last_id_row;
                            pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy, maxx);
                        }
                    }
                    else {
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
                    context = 1;
                    // TODO: print_device_files(device_pad, last_id, NULL);
                }
                else {
                }
            }
        }

        // update the ui
        if (context == 0) {
            werase(device_pad);
            print_devices(device_pad, dev_tree, &dev_IDs, &id_count, last_id, &last_id_row);
            pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy, maxx);
        }
        else {
            werase(device_pad);
            // TODO: print_device_files
            pnoutrefresh(device_pad, device_top_row, 0, 0, 0, maxy, maxx);
        }
        doupdate();
    }
    delwin(notification_win);
    delwin(device_pad);
    // delwin(devinfo_pad);
    // delwin(text_input_win);
    return 0;
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
        // TODO: check error codes, we don't want to print plain errors. error handle bbetter
        g_printerr("%s", err->message);
        g_clear_error(&err);
    }
    // print the current directory

    dir_entry = g_dir_read_name(curr_dir);
    while (dir_entry) {
        cpath = g_canonicalize_filename(dir_entry, NULL);
        if (!cpath) {
            g_dir_close(curr_dir);
            g_free(cpath);
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
    wmove(win_text, 1, 1);
    doupdate();

    while (1) {
        // get user input
        ret = get_user_input(win_text, &in_char);

        if (ret == OK) {
            if (in_char == '\x1b') {
                // if it is escape we exit
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
                    delwin(win);
                    delwin(win_frame);
                    delwin(win_text);
                    return -1;
                }

                // check if the user entered the current path to select it
                cwd = g_get_current_dir();
                if (strcmp(cwd, cpath) == 0) {
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
                    delwin(win);
                    delwin(win_frame);
                    delwin(win_text);
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

                ret = g_utf8_strlen(in_path, PATH_MAX - 1);
                if (ret > (win_c - 2))
                    mvwprintw(win_text, 1, 1, "%s", g_utf8_offset_to_pointer(in_path, ret - win_c + 2));
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
                    ret = g_utf8_strlen(in_path, PATH_MAX - 1);
                    if (ret > (win_c - 2))
                        mvwprintw(win_text, 1, 1, "%s", g_utf8_offset_to_pointer(in_path, ret - win_c + 2));
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
                        g_printerr("%s", err->message);
                        g_clear_error(&err);
                    }
                    // print the current directory

                    dir_entry = g_dir_read_name(curr_dir);
                    while (dir_entry) {
                        cpath = g_canonicalize_filename(dir_entry, NULL);
                        if (!cpath) {
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
                            mvwprintw(win, y, x, "%s", dir_entry);
                            ++y;
                        }
                        else {
                            // if it is a file or symlink print it in green
                            mvwprintw(win, y, x, "%s", dir_entry);
                            ++y;
                        }
                        g_free(cpath);
                        cpath = NULL;
                        dir_entry = g_dir_read_name(curr_dir);
                    }
                    g_dir_close(curr_dir);
                    pnoutrefresh(win, win_origin_y, win_origin_x, 1, 1, maxy - 5, maxx - 2);
                    ret = g_utf8_strlen(in_path, PATH_MAX - 1);
                    if (ret > (win_c - 2))
                        mvwprintw(win_text, 1, 1, "%s", g_utf8_offset_to_pointer(in_path, ret - win_c + 2));
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
    delwin(win);
    delwin(win_frame);
    delwin(win_text);
    return -1;
}

int print_devices(WINDOW *win, tree_t *dev_tree, unsigned char ***dev_IDs, size_t *id_count,
                  unsigned char last_id[crypto_sign_PUBLICKEYBYTES], int *last_row)
{
    int ret;
    int y = 0;
    uint64_t count = 0;
    tree_iterator_t *iter;
    remote_device_t *rdev;
    remote_device_t *found_rdev;
    remote_device_t s_rdev;
    known_key_t known_key;
    unsigned char **id_array = NULL;
    char highlight = 0;
    char found = 0;
    void *temp;

    if (!dev_IDs || !dev_tree || !win || !last_id || !last_row) {
        return -1;
    }

    memcpy(s_rdev.peer_pk, last_id, crypto_sign_PUBLICKEYBYTES);
    // searches the tree and does not unlock it
    if (dev_tree->search_pin(dev_tree, &s_rdev, (void **)&found_rdev)) {
        found = 1;
    }
    else {
        found = 0;
    }
    ret = new_tree_iterator(dev_tree, &iter);
    while (tree_has_next(iter)) {
        if (found && (memcmp(last_id, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES) == 0)) {
            // ignore the the device that was last highlighed
            // it will be printed on the same line it was before
            continue;
        }
        if (y == *last_row && found) {
            // print the last highlighed device on the row it was before
            print_device(win, found_rdev, count, 1);
            ++y;
            ++count;
            // add the device to the id array
            temp = reallocarray(id_array, count + 1, sizeof(unsigned char));
            if (!temp) {
                tree_unlock(dev_tree);
                return -1;
            }
            id_array = temp;
            temp = malloc(crypto_sign_PUBLICKEYBYTES);
            if (!temp) {
                tree_unlock(dev_tree);
                return -1;
            }
            id_array[count] = temp;
            memcpy(temp, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
            continue;
        }
        else if (y == *last_row && found == 0)
            highlight = 1;

        tree_next(iter, (void **)&rdev);

        print_device(win, rdev, count, highlight);
        ++y;
        ++count;

        highlight = 0;

        // add the device to the id array
        temp = reallocarray(id_array, count + 1, sizeof(unsigned char));
        if (!temp) {
            tree_unlock(dev_tree);
            return -1;
        }
        id_array = temp;
        temp = malloc(crypto_sign_PUBLICKEYBYTES);
        if (!temp) {
            tree_unlock(dev_tree);
            return -1;
        }
        id_array[count] = temp;
        memcpy(temp, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
    }
    if (found && count < *last_row) {
        // some devises got removed, so we print the our device at the end
        print_device(win, found_rdev, count, 1);
        ++count;
        *last_row = count;

        // add the device to the id array
        temp = reallocarray(id_array, count + 1, sizeof(unsigned char));
        if (!temp) {
            tree_unlock(dev_tree);
            return -1;
        }
        id_array = temp;
        temp = malloc(crypto_sign_PUBLICKEYBYTES);
        if (!temp) {
            tree_unlock(dev_tree);
            return -1;
        }
        id_array[count] = temp;
        memcpy(temp, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
    }
    else if (!found && count < *last_row) {
        // if we havent highlighed any device yet, we highlight the last one
        // that is because we have less devises than before and the last one is not there
        // so the lowest device above the last device is the last one printed
        wmove(win, count, 0);
        wchgat(win, 3, A_REVERSE, 0, NULL);
        *last_row = count;
        memcpy(last_id, rdev->peer_pk, crypto_sign_PUBLICKEYBYTES);
    }

    tree_unlock(dev_tree);

    *id_count = count + 1;
    *dev_IDs = id_array;

    return 0;
}

int print_device(WINDOW *win, remote_device_t *rdev, uint64_t count, char highlight)
{
    char *username;
    uint8_t *ip_bytes;
    known_key_t known_key;
    if (!win || !rdev)
        return -1;

    username = g_utf8_make_valid(rdev->username, MAX_USERNAME_LEN * sizeof(uint32_t));
    if (!username)
        return -1;
    if (g_utf8_strlen(username, -1) > MAX_USERNAME_LEN) {
        *(g_utf8_offset_to_pointer(username, MAX_USERNAME_LEN)) = '\0';
    }

    wmove(win, count, 0);
    wprintw(win, "dev%lu ", count);
    wattron(win, COLOR_PAIR(5));
    wprintw(win, "%s ", username);
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
    else if (rdev->dev_state_flag & KNOWN_KEY_STATUS_UNKOWN) {
        wattron(win, COLOR_PAIR(3));
        wprintw(win, "[UNKOWN]");
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
    g_free(username);

    if (highlight) {
        wmove(win, count, 0);
        wchgat(win, 3, A_REVERSE, 0, NULL);
    }
    return -1;
}

int print_device_files(WINDOW *win, unsigned char id[32], tree_t *dev_tree, lht_t *active_files)
{
    int ret;
    int y = 0;
    int i;
    size_t file_size;
    char *username;
    char *file_name;
    char *units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    remote_device_t rdev;
    remote_device_t *found_rdev;
    lht_node_t *af_node = NULL;
    active_file_t *af = NULL;

    if (!win || !dev_tree || !active_files)
        return -1;

    memcpy(rdev.peer_pk, id, crypto_sign_PUBLICKEYBYTES);
    ret = dev_tree->search_pin(dev_tree, &rdev, (void **)&found_rdev);
    if (ret == 0) {
        // the device was not found
        // we return with an error
        tree_unlock(dev_tree);
        return 1;
    }

    username = g_utf8_make_valid(rdev.username, MAX_USERNAME_LEN * sizeof(uint32_t));
    if (!username) {
        tree_unlock(dev_tree);
        return -1;
    }
    if (g_utf8_strlen(username, -1) > MAX_USERNAME_LEN) {
        *(g_utf8_offset_to_pointer(username, MAX_USERNAME_LEN)) = '\0';
    }

    wmove(win, 0, 0);

    wprintw(win, "%s", username);
    g_free(username);
    wmove(win, ++y, 0);
    for (int i = 0; i < 32; ++i) {
        wprintw(win, "%02x", id[i]);
    }

    wmove(win, ++y, 0);
    mvwprintw(win, ++y, 0, "[actions]");
    mvwprintw(win, ++y, 0, ">send a file...");
    mvwprintw(win, ++y, 0, ">trust this device.");
    mvwprintw(win, ++y, 0, ">super trust this device.");
    mvwprintw(win, ++y, 0, ">device is EVIL and SINISTER.");

    wmove(win, ++y, 0);
    mvwprintw(win, ++y, 0, "[requests]");
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
    }
    tree_unlock(dev_tree);

    wmove(win, ++y, 0);
    mvwprintw(win, ++y, 0, "[active files]");
    // TODO: we need a way to get all file transfers happening right now
    //       make a tree that is shared between send thread, packet handler and ui_queue
    //       each node has a file id, file name, persentage, and probably speed

    return 0;
}
