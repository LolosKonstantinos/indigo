//
// Created by Constantin on 04/10/2025.
//

#include "crypto_utils.h"
#include "cli.h"
#include "indigo_types.h"
#include <locale.h>
#include <wctype.h>
#include "indigo_errors.h"
#include <indigo_core/manager.h>


int verify_user(void** master_key) {
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
            getmaxyx(stdscr,maxy,maxx);
            move((maxy/2) - 1,(maxx - 46)/2);
            printw("Trying to set up password creation settings...");
            move((maxy/2),(maxx - 45)/2);
            printw("Testing for optimal settings for your system.");
            move((maxy/2) + 1,(maxx - 31)/2);
            printw("This might take several minutes");
            refresh();
            Sleep(1000);
            ret = create_key_derivation_settings();
            if (ret != INDIGO_SUCCESS) {
                return ret;
            }
            clear();
            refresh();
            getmaxyx(stdscr,maxy,maxx);
            move(maxy/2, (maxx - 48) /2);
            printw("Password creation settings created successfully.");
            refresh();
            Sleep(3000);
            clear();
        }
        curs_set(1);
        create_new_password();
    }
    ret = verify_password(master_key);
    if (ret) {
        fprintf(stderr,"error in verify_password() called inside verify_user");
        return ret;
    }

    if (!signing_key_pair_exists()) {
        ret = create_signing_key_pair(*master_key);
        printf("did not crash %p", *master_key);
    }
    return ret;
}
//todo this function makes the process crash, probably segfault, does not verify password correctly in debug mode
int verify_password(void** master_key) {
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
        fprintf(stderr,"\nerror:memory allocation failed.\n");
        return -1;
    }
    sodium_memzero(psw, MAX_PSW_LEN + 1);

    password_window = create_welcome_screen();
    box(password_window,0,0);
    keypad(password_window, TRUE);
    wmove(password_window,1,1);
    refresh();
    wrefresh(password_window);


    while (1) {
        res = wget_wch(password_window,&ch);
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
            if (mch == '\n' || mch == '\r') {enter = 1;}
            else if (mch == '\b' || mch == 127) {del = 1;}
            else if (mch > 127 || !(iswalnum(mch) || iswspecialchar(mch))){
                move(20,0);//todo check this to be bellow the password window
                printw("use ONLY alpharithmetics and !@#$%%^&*_");
                refresh();
                wmove(password_window,1,1 + ((psw_len >= 62)? 61: psw_len));
                wrefresh(password_window);
            }
            else {
                if (psw_len < MAX_PSW_LEN) {
                    if (err_printed) {
                        wclear(password_window);
                        box(password_window,0,0);
                        wmove(password_window,1,1);
                        wrefresh(password_window);
                        err_printed = 0;
                    }
                    if (psw_len < 62) wprintw(password_window, "*");
                    psw[psw_len] = mch;
                    psw_len++;
                }
                else{
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
            box(password_window,0,0);

            ret = cmp_password_hash(psw, psw_len);
            if (ret == 0) {
                break;
            }
            if (ret == 1 || overflow) {
                attron(COLOR_PAIR(1));
                mvwprintw(password_window,1,1,"PASSWORD INCORRECT. TRY AGAIN");
                attroff(COLOR_PAIR(1));
                wmove(password_window, 1,1);
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

            if (psw_len > 0){psw_len--;}
            psw[psw_len] = '\0';
            wmove(password_window,1,1 + ((psw_len >= 62)? 61: psw_len));
            wprintw(password_window, " ");
            wmove(password_window,1,1 + ((psw_len >= 62)? 61: psw_len));

        }
    }
    //the password is verified, and we now derive the master key
    ret = derive_master_key(psw,psw_len,master_key);
    if (ret != 0 || !*master_key) {
        sodium_memzero(psw, MAX_PSW_LEN);
        sodium_free(psw);
        delwin(password_window);
        clear();
        refresh();
        printf("derive master key return: %d\n",ret);
        return ret;
    }
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
    password_window = newwin(3,64,17,(maxx -64)/2);
    mvprintw(0,(maxx -64)/2,    " _       __________    __________  __  _________   __________   ");
    mvprintw(1,(maxx -64)/2,    "| |     / / ____/ /   / ____/ __ \\/  |/  / ____/  /_  __/ __ \\");
    mvprintw(2,(maxx -64)/2,    "| | /| / / __/ / /   / /   / / / / /|_/ / __/      / / / / / /  ");
    mvprintw(3,(maxx -64)/2,    "| |/ |/ / /___/ /___/ /___/ /_/ / /  / / /___     / / / /_/ /   ");
    mvprintw(4,(maxx -64)/2,    "|__/|__/_____/_____/\\____/\\____/_/__/_/_____/    /_/  \\____/ ");
    mvprintw(5,(maxx -64)/2,    "              /  _/ | / / __ \\/  _/ ____/ __ \\                ");
    mvprintw(6,(maxx -64)/2,    "              / //  |/ / / / // // / __/ / / /                  ");
    mvprintw(7,(maxx -64)/2,    "            _/ // /|  / /_/ // // /_/ / /_/ /                   ");
    mvprintw(8,(maxx -64)/2,    "           /___/_/ |_/_____/___/\\____/\\____/                  ");
    mvprintw(16, (maxx - 26)/2, "PLEASE ENTER YOUR PASSWORD");

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
    wint_t ch;
    char mch;
    int res = 0;
    char enter = 0;
    char del = 0;
    char err_writen = 0;

    int maxx = getmaxx(stdscr);
    noecho();
    psw_1 = sodium_malloc(MAX_PSW_LEN + 1);
    if (!psw_1) { return 1;}
    psw_2 = sodium_malloc(MAX_PSW_LEN + 1);
    if (!psw_2) {
        sodium_free(psw_1);
        return 1;
    }
    sodium_memzero(psw_1, MAX_PSW_LEN + 1);
    sodium_memzero(psw_2, MAX_PSW_LEN + 1);
    psw_win_1 = newwin(3,64,16,(maxx -64)/2);
    psw_win_2 = newwin(3,64,22,(maxx -64)/2);
    box(psw_win_1,0,0);
    box(psw_win_2,0,0);
    //the welcome message
    {
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
    }
    move(12,(maxx - 25)/2);
    printw("Your password is not set.");
    move(13,(maxx -25)/2);
    printw(" Let's create a new one!");
    move(15,0);
    printw("Enter your password bellow (just type and hit enter when done): ");
    move(21,0);
    printw("Re-enter your password to verify it.");
    keypad(psw_win_1,TRUE);
    keypad(psw_win_2,TRUE);
    curr_window = psw_win_1;

    refresh();
    wmove(psw_win_1,1,1);
    wrefresh(psw_win_1);
    wrefresh(psw_win_2);
    wmove(psw_win_1,1,1);
    while (1) {
        res = wget_wch(curr_window,&ch);
        mch = (char)(ch & 0xff);
        if (res == KEY_CODE_YES) {
            switch (ch) {
                case KEY_UP:
                wmove(psw_win_1,1,1 + ((psw_len_1 > 62)? 60: psw_len_1));
                curr_window = psw_win_1;
                break;
                case KEY_DOWN:
                wmove(psw_win_2,1,1 + ((psw_len_2 > 62)? 60: psw_len_2));
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
            if (ch == '\n' || ch == '\r') {enter = 1;}
            else if (ch == '\b' || ch == 127) {del = 1;}
            else if (ch > 127 || !(iswalnum(ch) || iswspecialchar(ch))){
                move(19,0);
                printw("use ONLY alpharithmetics and !@#$%%^&*_");
                refresh();

                if (curr_window == psw_win_1) {
                    wmove(psw_win_1,1,1 + ((psw_len_1 > 62)? 61: psw_len_1));
                    wrefresh(psw_win_1);
                }
                else {
                    wmove(psw_win_2,1,1 + ((psw_len_2 > 62)? 61: psw_len_2));
                    wrefresh(psw_win_2);
                }
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
                        if (psw_len_1 < 62){ wprintw(curr_window, "*");}
                        psw_1[psw_len_1] = mch;
                        psw_len_1++;
                    }
                }
                else {
                    if (psw_len_2 < MAX_PSW_LEN) {
                        if (psw_len_2 < 62){wprintw(curr_window, "*");}
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
                wmove(psw_win_2,1,1 + ((psw_len_2 > 62)? 60: psw_len_2));
                curr_window = psw_win_2;
                continue;
            }
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
        if (del) {
            del = 0;
            if (curr_window == psw_win_1) {
                if (psw_len_1 > 0){psw_len_1--;}
                psw_1[psw_len_1] = '\0';
                wmove(psw_win_1,1,1 + ((psw_len_1 >= 62)? 61: psw_len_1));
                wprintw(psw_win_1, " ");
                wmove(psw_win_1,1,1 + ((psw_len_1 >= 62)? 61: psw_len_1));
            }
            else {
                if (psw_len_2 > 0){psw_len_2--;}
                psw_2[psw_len_2] = '\0';
                wmove(psw_win_2,1,1 + ((psw_len_2 >= 62)? 61: psw_len_2));
                wprintw(psw_win_2, " ");
                wmove(psw_win_2,1,1 + ((psw_len_2 >= 62)? 61: psw_len_2));
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
int iswspecialchar(const wint_t ch) {
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

//the main screen
int init_main_interface() {}