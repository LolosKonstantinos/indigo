//
// Created by Constantin on 04/10/2025.
//

#include "crypto_utils.h"
#include "cli.h"

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
    char psw[128];
    int c, overflow = 0, ret = 0;
    size_t psw_len = 0;



    printw("Please enter the password:\n(password is not visible for security)\n>");
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    refresh();



    do {
        if (ret != 0){
            printw("\nInvalid password, please try again!\n>");
            refresh();
            overflow = 0;
            psw_len = 0;
        }
        if (ret == -1) return -1;

        while (c = getch(), c != '\n') {
            if (c == KEY_BACKSPACE) {
                //the character 8 is the backspace
                if (psw_len > 0) psw_len--;
                continue;
            }
            //the printable range
            if (c< 32 || c > 126) {
                attron(COLOR_PAIR(1));
                printw("\nInvalid character detected, please try again.\nEnter password bellow.\n>");
                refresh();
                attroff(COLOR_PAIR(1));
                psw_len = 0;
                continue;
            }


            if (psw_len == 128 - 1) {
                overflow = 1;
                continue;
            }

            psw[psw_len++] = (char)c;
        }
        psw[psw_len] = '\0';
    }while (ret = cmp_password_hash(psw, 127), ret == 1 || overflow);

    sodium_memzero(psw, 128);

    return 0;
}
