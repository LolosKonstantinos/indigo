//
// Created by Constantin on 04/10/2025.
//

#include "crypto_utils.h"
#include "cli.h"
#include "indigo_types.h"
#include <ctype.h>

#include "indigo_errors.h"


int init_cli() {
    initscr();
    init_pair(1, COLOR_RED, COLOR_BLACK);
    if (!verify_password()) {
        printw("BUG IN verify_password() called inside init_cli");
        refresh();
        return -1;
    }

    endwin();
    return 0;
}
int verify_password(void) {
    char *psw;
    int c;
    int overflow = 0;
    int ret = 0;
    size_t psw_len = 0;
    WINDOW *password_window;

    psw = sodium_malloc(MAX_PSW_LEN);
    if (psw == NULL) {
        printw("\nerror:memory allocation failed.\n");
        refresh();
        return -1;
    }
    password_window = create_welcome_screen();
    noecho();
    keypad(stdscr, TRUE);
    refresh();


    do {
        if (ret != 0){
            attron(COLOR_PAIR(1));
            wmove(password_window,0,0);
            wprintw(password_window,"Invalid password, please try again!");
            attroff(COLOR_PAIR(1));
            wrefresh(password_window);
            overflow = 0;
            psw_len = 0;
        }
        if (ret == -1) {
            sodium_free(psw);
            return -1;
        }

        while (c = getch(), c != '\n') {
            if (c == KEY_BACKSPACE) {
                if (psw_len > 0) {
                    psw_len--;
                    wmove(password_window,0,0);
                    for (int i = 0; i < psw_len; i++) {
                        wprintw(password_window,"*");
                    }
                }
                continue;
            }
            //if the character is not in the printable range
            if (c < 32 || c > 126) {
                attron(COLOR_PAIR(1));
                wmove(password_window,0,0);
                wprintw(password_window,"Invalid character detected, please try again.");
                wrefresh(password_window);
                attroff(COLOR_PAIR(1));
                psw_len = 0;
                continue;
            }


            if (psw_len == MAX_PSW_LEN - 1) {
                overflow = 1;
                continue;
            }

            psw[psw_len++] = (char)c;
            wprintw(password_window,"*");
        }
        psw[psw_len] = '\0';
    }while (ret = cmp_password_hash(psw, MAX_PSW_LEN - 1), ret == 1 || overflow);

    sodium_memzero(psw, MAX_PSW_LEN);
    sodium_free(psw);
    delwin(password_window);
    clear();
    refresh();
    return 0;
}

WINDOW *create_welcome_screen() {
    WINDOW *password_window;
    const int maxx = getmaxx(stdscr);
    password_window = newwin(3,64,13,(maxx -64)/2);
    wrefresh(password_window);
    box(password_window,0,0);
    mvprintw(0,(maxx -64)/2,   " _       __________    __________  __  _________   __________   \n"
                               "| |     / / ____/ /   / ____/ __ \\/  |/  / ____/  /_  __/ __ \\\n"
                               "| | /| / / __/ / /   / /   / / / / /|_/ / __/      / / / / / /  \n"
                               "| |/ |/ / /___/ /___/ /___/ /_/ / /  / / /___     / / / /_/ /   \n"
                               "|__/|__/_____/_____/\\____/\\____/_/__/_/_____/    /_/  \\____/ \n"
                               "              /  _/ | / / __ \\/  _/ ____/ __ \\                \n"
                               "              / //  |/ / / / // // / __/ / / /                  \n"
                               "            _/ // /|  / /_/ // // /_/ / /_/ /                   \n"
                               "           /___/_/ |_/_____/___/\\____/\\____/                    ");
    mvprintw(12, (maxx - 26)/2, "PLEASE ENTER YOUR PASSWORD");
    return password_window;
}

int create_new_password() {
    WINDOW *psw_win_1;
    WINDOW *psw_win_2;
    WINDOW *curr_window;
    char *psw_1;
    char *psw_2;
    int psw_len_1 = 0;
    int psw_len_2 = 0;
    int ch;
    char mch;
    char err_writen = 0;

    int maxx = getmaxx(stdscr);
    noecho();
    psw_1 = sodium_malloc(MAX_PSW_LEN);
    if (!psw_1) { return 1;}
    psw_2 = sodium_malloc(MAX_PSW_LEN);
    if (!psw_2) {
        sodium_free(psw_1);
        return 1;
    }
    sodium_memzero(psw_1, MAX_PSW_LEN);
    sodium_memzero(psw_2, MAX_PSW_LEN);
    psw_win_1 = newwin(3,64,16,(maxx -64)/2);
    psw_win_2 = newwin(3,64,22,(maxx -64)/2);
    box(psw_win_1,0,0);
    box(psw_win_2,0,0);
    move(0,(maxx -76)/2);
    printw(  " _    _ ______ _      _      ____    _______ _    _ ______ _____  ______    ");
    move(1,(maxx -76)/2);
    printw(  "| |  | |  ____| |    | |    / __ \\  |__   __| |  | |  ____|  __ \\|  ____| ");
    move(2,(maxx -76)/2);
    printw(  "| |__| | |__  | |    | |   | |  | |    | |  | |__| | |__  | |__) | |__      ");
    move(3,(maxx -76)/2);
    printw(  "|  __  |  __| | |    | |   | |  | |    | |  |  __  |  __| |  _  /|  __|     ");
    move(4,(maxx -76)/2);
    printw(  "| |  | | |____| |____| |___| |__| |    | |  | |  | | |____| | \\ \\| |____  ");
    move(5,(maxx -76)/2);
    printw(  "|_|  |_|______|______|______\\____/____ |_|_ |_|  |_|______|_|__\\_\\______|");
    move(6,(maxx -76)/2);
    printw(  "      | \\ | |  ____\\ \\        / / ____/ __ \\|  \\/  |  ____|  __ \\     ");
    move(7,(maxx -76)/2);
    printw(  "      |  \\| | |__   \\ \\  /\\  / / |   | |  | | \\  / | |__  | |__) |     ");
    move(8,(maxx -76)/2);
    printw(  "      | . ` |  __|   \\ \\/  \\/ /| |   | |  | | |\\/| |  __| |  _  /       ");
    move(9,(maxx -76)/2);
    printw(  "      | |\\  | |____   \\  /\\  / | |___| |__| | |  | | |____| | \\ \\      ");
    move(10,(maxx -76)/2);
    printw(  "      |_| \\_|______|   \\/  \\/   \\_____\\____/|_|  |_|______|_|  \\_\\   ");
    move(12,(maxx - 25)/2);
    printw("Your password is not set.");
    move(13,(maxx -25)/2);
    printw(" Let's create a new one!");
    move(15,0);
    printw("Enter your password bellow (just type and hit enter when done): ");
    move(21,0);
    printw("Re-enter your password to verify it.");
    wmove(psw_win_1, 1,1);
    keypad(psw_win_1,TRUE);
    keypad(psw_win_2,TRUE);
    curr_window = psw_win_1;

    refresh();
    wrefresh(psw_win_1);
    wrefresh(psw_win_2);

    while (1) {
        ch = wgetch(curr_window);
        mch = (char)(ch & 0xff);

        if (ch == '\n') {
            if (psw_len_1 != psw_len_2) {
                wclear(psw_win_1);
                wclear(psw_win_2);
                box(psw_win_1,0,0);
                box(psw_win_2,0,0);
                psw_len_1 = psw_len_2 = 0;
                sodium_memzero(psw_1, MAX_PSW_LEN);
                sodium_memzero(psw_2, MAX_PSW_LEN);
                wmove(psw_win_1,1,1);
                wprintw(psw_win_1,"passwords are not the same, please try again!");
                wrefresh(psw_win_1);
                wrefresh(psw_win_2);
                err_writen = 1;
                curr_window = psw_win_1;
                continue;
            }
            if (sodium_memcmp(psw_1, psw_2, MAX_PSW_LEN) == 0) {break;}

            wclear(psw_win_1);
            wclear(psw_win_2);
            box(psw_win_1,0,0);
            box(psw_win_2,0,0);
            psw_len_1 = psw_len_2 = 0;
            sodium_memzero(psw_1, MAX_PSW_LEN);
            sodium_memzero(psw_2, MAX_PSW_LEN);
            wmove(psw_win_1,1,1);
            wprintw(psw_win_1,"passwords are not the same, please try again!");
            wrefresh(psw_win_1);
            wrefresh(psw_win_2);
            err_writen = 1;
            curr_window = psw_win_1;
            continue;

        }
        //checks if the first bit of the character part is 1 (in that case we got a multibyte character)
        if (ch == KEY_UP) {
            wmove(psw_win_1,1,1 + ((psw_len_1 > 62)? 61: psw_len_1));
            curr_window = psw_win_1;
        }
        else if (ch == KEY_DOWN) {
            wmove(psw_win_2,1,1 + ((psw_len_2 > 62)? 61: psw_len_2));
            curr_window = psw_win_2;
        }
        else if (ch & 0x80 || (!isalpha(mch) && !ispunct(mch))) {
            move(19,0);
            printw("use ONLY alpharithmetics and !@#$%%^&*-+=_()[]{}.,;:?'\"~\\/|");
            wrefresh(psw_win_1);
            wrefresh(psw_win_2);
            if (curr_window == psw_win_1) {
                wmove(psw_win_1,1,1 + ((psw_len_1 > 62)? 61: psw_len_1));
            }
            else{wmove(psw_win_2,1,1 + ((psw_len_2 > 62)? 61: psw_len_2));}
            continue;
        }
        else {
            if (curr_window == psw_win_1) {
                if (psw_len_1 < MAX_PSW_LEN) {
                    if (err_writen) {
                        wclear(psw_win_1);
                        box(psw_win_1,0,0);
                        wrefresh(psw_win_1);
                        wmove(psw_win_1,1,1);
                        err_writen = 0;
                    }
                    if (psw_len_1 < 63){ wprintw(curr_window, "*");}
                    psw_1[psw_len_1] = mch;
                    psw_len_1++;
                }
            }
            else {
                if (psw_len_2 < MAX_PSW_LEN) {
                    if (psw_len_2 < 63){wprintw(curr_window, "*");}
                    psw_2[psw_len_2] = mch;
                    psw_len_2++;
                }
            }

        }
    }
    ch = save_password_hash(psw_1, psw_len_1);
    if (ch != INDIGO_SUCCESS) {
        sodium_memzero(psw_1, MAX_PSW_LEN);
        sodium_memzero(psw_2, MAX_PSW_LEN);
        sodium_free(psw_1);
        sodium_free(psw_2);
        delwin(psw_win_1);
        delwin(psw_win_2);
        return ch;
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