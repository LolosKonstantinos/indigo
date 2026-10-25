#include <ui.h>

#include <indigo_errors.h>
#include <curses.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>
#include <sodium/utils.h>
#include <crypto_utils.h>
#include <logger.h>
#include <glib/gunicode.h>

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
    if (signing_key_pair_exists() == 0) {
        ret = create_signing_key_pair(*master_key);
        if (ret)
            log_error("[verify_user] create_signing_key_pair() failed | return %d", ret);
    }
    return ret;
}

int verify_password(void **master_key)
{
    char *psw;
    utf8_char_t ch;
    size_t char_len;
    int overflow = 0;
    int ret = 0;
    int res = 0;
    int psw_char_len = 0;
    int psw_byte_len = 0;
    int maxx;
    int maxy;
    int input_line_width;
    int printed_char_num;
    WINDOW *password_window;
    WINDOW *welcome_message;
    char err_printed = 0;

    psw = sodium_malloc(MAX_PSW_LEN + 1);
    if (psw == NULL) {
        log_error("[verify_password] sodium_malloc() failed allocating %d bytes for plaintext password | return %d",
                  MAX_PSW_LEN + 1, INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    sodium_memzero(psw, MAX_PSW_LEN + 1);

    welcome_message = newpad(9,64);
    if (!welcome_message) {
        sodium_free(psw);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    getmaxyx(stdscr,maxy,maxx);
    input_line_width = maxx > 66 ? 66 : maxx;

    password_window = newwin(3,input_line_width, maxy - 3, (maxx - input_line_width)/2);
    if (!password_window) {
        sodium_free(psw);
        delwin(welcome_message);
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }

    print_welcome_screen(welcome_message);

    box(password_window, 0, 0);
    keypad(password_window, TRUE);
    wmove(password_window, 1, 1);

    {
        const int xoffset = maxx > 64 ? 64 : maxx;
        const int yoffset = maxy > 9 ? 9 : maxy;
        pnoutrefresh(welcome_message,0,0,0,(maxx - xoffset)/2, yoffset, xoffset);
    }
    wnoutrefresh(password_window);
    doupdate();

    while (1) {
        ch = 0;
        res = get_user_input(password_window, &ch);

        if (res == OK) {
            if (ch == '\x1b') {
                // if it is escape we exit
                sodium_free(psw);
                delwin(password_window);
                delwin(welcome_message);
                clear();
                refresh();
                return 1;
            }

            if (ch == '\n' || ch == '\r') {
                wclear(password_window);
                box(password_window, 0, 0);

                ret = cmp_password_hash(psw, psw_char_len);
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
                    psw_char_len = 0;
                    sodium_memzero(psw, MAX_PSW_LEN + 1);
                }
                else {
                    sodium_free(psw);
                    delwin(password_window);
                    delwin(welcome_message);
                    clear();
                    refresh();
                    return -1;
                }
                wrefresh(password_window);
                break;
            }

            if (char_len = strlen((char *)&ch), psw_byte_len + char_len< MAX_PSW_LEN){
                strcat(psw, (char *)&ch);
                ++psw_char_len;
                psw_byte_len += (int)char_len;

                werase(password_window);
                box(password_window, 0, 0);

                wmove(password_window, 1,1);

                printed_char_num = psw_char_len > input_line_width? input_line_width - 2 : psw_char_len;
                printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                for (int i = 0; i < printed_char_num; i++) {
                    wprintw(password_window,"*");
                }
                wnoutrefresh(password_window);
            }
        }
        else if (res == KEY_CODE_YES) {
            switch (ch) {
                case KEY_BACKSPACE:
                    // delete the last character
                    *((char *)(g_utf8_offset_to_pointer(psw, g_utf8_strlen(psw, PATH_MAX) - 1))) = '\0';
                    --psw_char_len;
                    psw_byte_len = (int)strlen(psw);
                    werase(password_window);
                    box(password_window, 0, 0);
                    wmove(password_window, 1,1);

                    printed_char_num = psw_char_len > input_line_width? input_line_width - 2 : psw_char_len;
                    printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                    for (int i = 0; i < printed_char_num; i++) {
                        wprintw(password_window,"*");
                    }
                    break;
                case KEY_DC:
                case KEY_LEFT:
                case KEY_RIGHT:
                case KEY_UP:
                case KEY_DOWN:
                case KEY_RESIZE:
                    // resize the window
                    werase(password_window);
                    wnoutrefresh(password_window);
                    doupdate();
                    getmaxyx(stdscr, maxy, maxx);

                    input_line_width = maxx > 66 ? 66 : maxx;
                    wresize(password_window, 3, input_line_width);
                    box(password_window, 0, 0);

                    {
                        const int xoffset = maxx > 64 ? 64 : maxx;
                        const int yoffset = maxy > 9? 9 : maxy;
                        pnoutrefresh(welcome_message,0,0,0,(maxx - xoffset)/2, yoffset, xoffset);
                    }

                    wmove(password_window, 1,1);

                    printed_char_num = psw_char_len > input_line_width? input_line_width - 2 : psw_char_len;
                    printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                    for (int i = 0; i < printed_char_num; i++) {
                        wprintw(password_window,"*");
                    }
                    wnoutrefresh(password_window);
                    doupdate();

                    break;
                default:
                    break;
            }
        }
        else {
            sodium_memzero(psw, MAX_PSW_LEN);
            sodium_free(psw);
            delwin(password_window);
            delwin(welcome_message);
            clear();
            refresh();
            log_error("[verify_password] get_user_input() failed | return %d", ret);
            return ret;
        }
        doupdate();
    }
    // the password is verified, and we now derive the master key
    ret = derive_master_key(psw, psw_char_len, master_key);
    if (ret != 0 || !*master_key) {
        sodium_free(psw);
        delwin(password_window);
        delwin(welcome_message);
        clear();
        refresh();
        log_error("[verify_password] derive_master_key() failed | return %d", ret);
        return ret;
    }

    sodium_free(psw);
    delwin(password_window);
    delwin(welcome_message);
    clear();
    refresh();
    return 0;
}

void print_welcome_screen(WINDOW *password_window)
{
    const int maxx = getmaxx(stdscr);

    if (!password_window) return;

    // password_window = newwin(3, 64, 17, (maxx - 64) / 2);
    mvwprintw(password_window, 0, (maxx - 64) / 2, " _       __________    __________  __  _________   __________   ");
    mvwprintw(password_window, 1, (maxx - 64) / 2, "| |     / / ____/ /   / ____/ __ \\/  |/  / ____/  /_  __/ __ \\");
    mvwprintw(password_window, 2, (maxx - 64) / 2, "| | /| / / __/ / /   / /   / / / / /|_/ / __/      / / / / / /  ");
    mvwprintw(password_window, 3, (maxx - 64) / 2, "| |/ |/ / /___/ /___/ /___/ /_/ / /  / / /___     / / / /_/ /   ");
    mvwprintw(password_window, 4, (maxx - 64) / 2, "|__/|__/_____/_____/\\____/\\____/_/__/_/_____/    /_/  \\____/ ");
    mvwprintw(password_window, 5, (maxx - 64) / 2, "              /  _/ | / / __ \\/  _/ ____/ __ \\                ");
    mvwprintw(password_window, 6, (maxx - 64) / 2, "              / //  |/ / / / // // / __/ / / /                  ");
    mvwprintw(password_window, 7, (maxx - 64) / 2, "            _/ // /|  / /_/ // // /_/ / /_/ /                   ");
    mvwprintw(password_window, 8, (maxx - 64) / 2, "           /___/_/ |_/_____/___/\\____/\\____/                  ");
    //mvprintw(16, (maxx - 26) / 2, "PLEASE ENTER YOUR PASSWORD");
}

int create_new_password()
{
    WINDOW *psw_win_1;
    WINDOW *psw_win_2;
    WINDOW *curr_window;
    char *psw_1;
    char *psw_2;
    int psw_char_len1 = 0;
    int psw_byte_len1 = 0;
    int psw_char_len2 = 0;
    int psw_byte_len2 = 0;
    int input_line_width;
    utf8_char_t ch;
    size_t char_len;
    int res = 0;
    int ret = 0;
    char enter = 0;
    char del = 0;
    char err_writen = 0;
    int maxx;
    int maxy;

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

    getmaxyx(stdscr, maxy, maxx);
    input_line_width = maxx > 66? 66: maxx;

    psw_win_1 = newwin(3, input_line_width, 4, (maxx - input_line_width) / 2);
    psw_win_2 = newwin(3, input_line_width, 9, (maxx - input_line_width) / 2);
    box(psw_win_1, 0, 0);
    box(psw_win_2, 0, 0);
    // the welcome message


    move(0, (maxx - 25) / 2);
    printw("Your password is not set.");
    move(1, (maxx - 23) / 2);
    printw("Let's create a new one!");
    move(3, 0);
    printw("Enter your password bellow (just type and hit enter when done): ");
    move(8, 0);
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
        res = get_user_input(curr_window, &ch);
        if (res == OK) {
            if (ch == '\x1b') {
                // if it is escape we exit
                sodium_free(psw_1);
                sodium_free(psw_2);
                delwin(psw_win_1);
                delwin(psw_win_2);
                clear();
                refresh();
                return 1;
            }

            if (ch == '\n' || ch == '\r') {
                werase(psw_win_1);
                werase(psw_win_2);
                box(psw_win_1, 0, 0);
                box(psw_win_2, 0, 0);

                if (curr_window == psw_win_1) {
                    const int input_text_len = input_line_width > 2 ? 0 : input_line_width-2;
                    wmove(psw_win_2, 1, 1 + (psw_char_len2 > input_text_len ? input_text_len : psw_char_len2));
                    curr_window = psw_win_2;
                    continue;
                }

                if (sodium_memcmp(psw_1, psw_2, MAX_PSW_LEN) == 0) {
                    break;
                }

                wclear(psw_win_1);
                wclear(psw_win_2);
                box(psw_win_1, 0, 0);
                box(psw_win_2, 0, 0);
                psw_char_len1 = psw_char_len2 = 0;
                psw_byte_len1 = psw_byte_len2 = 0;
                sodium_memzero(psw_1, MAX_PSW_LEN);
                sodium_memzero(psw_2, MAX_PSW_LEN);
                wmove(psw_win_1, 1, 1);
                wprintw(psw_win_1, "passwords don't match, try again!");
                wrefresh(psw_win_1);
                wrefresh(psw_win_2);
                err_writen = 1;
                curr_window = psw_win_1;
                continue;
            }
            if (curr_window == psw_win_1) {
                if (char_len = strlen((char *)&ch), psw_byte_len1 + char_len< MAX_PSW_LEN){
                    int printed_char_num;
                    strcat(psw_1, (char *)&ch);
                    ++psw_char_len1;
                    psw_byte_len1 += (int)char_len;

                    werase(psw_win_1);
                    box(psw_win_1, 0, 0);

                    wmove(psw_win_1, 1,1);

                    printed_char_num = psw_char_len1 > input_line_width? input_line_width - 2 : psw_char_len1;
                    printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                    for (int i = 0; i < printed_char_num; i++) {
                        wprintw(psw_win_1, "*");
                    }
                    wnoutrefresh(psw_win_1);
                }
            }
            else {
                if (char_len = strlen((char *)&ch), psw_byte_len2 + char_len< MAX_PSW_LEN){
                    int printed_char_num;
                    strcat(psw_2, (char *)&ch);
                    ++psw_char_len2;
                    psw_byte_len2 += (int)char_len;

                    werase(psw_win_2);
                    box(psw_win_2, 0, 0);

                    wmove(psw_win_2, 1,1);

                    printed_char_num = psw_char_len2 > input_line_width? input_line_width - 2 : psw_char_len2;
                    printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                    for (int i = 0; i < printed_char_num; i++) {
                        wprintw(psw_win_2,"*");
                    }
                    wnoutrefresh(psw_win_2);
                }
            }

        }
        else if (res == KEY_CODE_YES) {
            switch (ch) {
                case KEY_BACKSPACE:
                    // delete the last character
                    if (curr_window == psw_win_1) {
                        int printed_char_num;
                        *((char *)(g_utf8_offset_to_pointer(psw_1, g_utf8_strlen(psw_1, PATH_MAX) - 1))) = '\0';
                        --psw_char_len1;
                        psw_byte_len1 = (int)strlen(psw_1);
                        werase(psw_win_1);
                        box(psw_win_1, 0, 0);
                        wmove(psw_win_1, 1,1);

                        printed_char_num = psw_char_len1 > input_line_width? input_line_width - 2 : psw_char_len1;
                        printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                        for (int i = 0; i < printed_char_num; i++) {
                            wprintw(psw_win_1,"*");
                        }
                    }
                    else {
                        int printed_char_num;
                        *((char *)(g_utf8_offset_to_pointer(psw_2, g_utf8_strlen(psw_2, PATH_MAX) - 1))) = '\0';
                        --psw_char_len2;
                        psw_byte_len2 = (int)strlen(psw_2);
                        werase(psw_win_2);
                        box(psw_win_2, 0, 0);
                        wmove(psw_win_2, 1,1);

                        printed_char_num = psw_char_len2 > input_line_width? input_line_width - 2 : psw_char_len2;
                        printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                        for (int i = 0; i < printed_char_num; i++) {
                            wprintw(psw_win_2,"*");
                        }
                    }

                    break;
                case KEY_DC:
                case KEY_LEFT:
                case KEY_RIGHT:
                    break;
                case KEY_UP: {
                    const int input_text_len = input_line_width > 2 ? 0 : input_line_width-2;
                    wmove(psw_win_1, 1, 1 + (psw_char_len1 > input_text_len ? input_text_len : psw_char_len1));
                    curr_window = psw_win_1;
                    break;
                }
                case KEY_DOWN: {
                    const int input_text_len = input_line_width > 2 ? 0 : input_line_width-2;
                    wmove(psw_win_2, 1, 1 + (psw_char_len2 > input_text_len ? input_text_len : psw_char_len2));
                    curr_window = psw_win_2;
                    break;
                }
                case KEY_RESIZE: {
                    int printed_char_num;
                    const int input_text_len = input_line_width > 2 ? 0 : input_line_width-2;
                    // resize the window
                    werase(psw_win_1);
                    werase(psw_win_2);
                    wnoutrefresh(psw_win_1);
                    wnoutrefresh(psw_win_2);
                    doupdate();
                    getmaxyx(stdscr, maxy, maxx);

                    box(psw_win_1, 0, 0);
                    box(psw_win_2, 0, 0);

                    move(0, (maxx - 25) / 2);
                    printw("Your password is not set.");
                    move(1, (maxx - 23) / 2);
                    printw("Let's create a new one!");
                    move(3, 0);
                    printw("Enter your password bellow (type and hit enter when done):");
                    move(8, 0);
                    printw("Re-enter your password to verify it.");

                    wmove(psw_win_1, 1,1);

                    printed_char_num = psw_char_len1 > input_line_width? input_line_width - 2 : psw_char_len1;
                    printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                    for (int i = 0; i < printed_char_num; i++) {
                        wprintw(psw_win_1,"*");
                    }
                    wnoutrefresh(psw_win_1);

                    wmove(psw_win_2, 1,1);

                    printed_char_num = psw_char_len2 > input_line_width? input_line_width - 2 : psw_char_len2;
                    printed_char_num = printed_char_num < 0 ? 0: printed_char_num;

                    for (int i = 0; i < printed_char_num; i++) {
                        wprintw(psw_win_1,"*");
                    }
                    wnoutrefresh(psw_win_2);

                    if (curr_window == psw_win_1) {
                        wmove(psw_win_1, 1, 1 + (psw_char_len1 > input_text_len ? input_text_len : psw_char_len1));
                    }
                    else {
                        wmove(psw_win_2, 1, 1 + (psw_char_len2 > input_text_len ? input_text_len : psw_char_len2));
                    }


                    doupdate();

                    break;
                }
                default:
                    break;
            }
        }
        else {
            sodium_free(psw_1);
            sodium_free(psw_2);
            delwin(psw_win_1);
            delwin(psw_win_2);
            clear();
            refresh();
            log_error("[verify_password] get_user_input() failed | return %d", ret);
            return ret;
        }
    }

    res = save_password_hash(psw_1, psw_char_len1);
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