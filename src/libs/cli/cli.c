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
#include <crypto_utils.h>
#include "indigo_types.h"
#include "indigo_errors.h"

#ifdef WIN32
#include <windef.h>
#include <Winbase.h>
#include <WinCon.h>
#else
/*assume Linux*/
#include <sys/ioctl.h>
#include <unistd.h>
#endif
#define FORCE_INLINE inline __attribute__((always_inline))
struct progress_bar_t {
    int x;
    int y;
    int width;
    char percentage;
    char zero[3];
};

int get_src_size(int *rows, int *cols) {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;

    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info) == 0)
        return -1;

    if (rows) *rows = info.dwSize.Y;
    if (cols) *cols = info.dwSize.X;
#else
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    
    if (rows) *rows = w.ws_row;
    if (cols) *cols = w.ws_col;
#endif
    return 0;
}

FORCE_INLINE void clear_screen() {
    printf("\x1B[2J\x1B[H");
}

FORCE_INLINE void delete_lines(const int count) {
    for (int i = 0; i < count; i++) printf("\x1bM\x1b[2K");
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
    free(*progress_bar);
    *progress_bar = NULL;
    return 0;
}
int update_progress_bar(progress_bar_t *progress_bar, char progress) {
    if (!progress_bar) return -1;
    progress_bar->percentage = progress;
    return 0;
}
int move_progress_bar(progress_bar_t *progress_bar, int x, int y) {
    if (!progress_bar) return -1;
    progress_bar->x = x;
    progress_bar->y = y;
    return 0;
}
int refresh_progress_bar(progress_bar_t *progress_bar) {
    char move[32] = "\x1b[";
    int char_count;
    if (!progress_bar) return -1;

    char_count = ((progress_bar->width - 2) * progress_bar->percentage)/100;

    //prepare the string to move to the position of the progress bar
    sprintf(move + 5, "%d", progress_bar->y);
    strcat(move, "};{");
    sprintf(move + strlen(move), "%d", progress_bar->x);
    strcat(move, "}H");

    //save the cursor position
    printf("\277");
    //move to the progress bar
    move[31] = '\0'; //for safety, I don't think anything could happen
    printf(move);

    putchar('[');

    for (int i = 0; i < char_count; i++) putchar('#');
    for (int i = 0; i < progress_bar->width - 2 - char_count; i++) putchar(' ');

    putchar(']');

    //move to the saved cursor position
    printf("\278");
    return 0;
}

//login utils
void bypass_login(void **master_key) {
    derive_master_key("test", 4, master_key);
}

FORCE_INLINE int isspecialchar(const char ch) {
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
int password_is_valid(char psw[MAX_PSW_LEN + 1]) {
    if (!psw) return 0;

    psw[MAX_PSW_LEN] = '\0';

    for (int i = 0; i < MAX_PSW_LEN; i++) {
        if (psw[i] == '\0') break;
        if (psw[i] & (1<<7)) return 0;
        if (!(isalnum(psw[i]) || isspecialchar(psw[i]))) return 0;
    }
    return 1;
}

int create_new_password() {
    char *psw_1;
    char *psw_2;
    uint32_t len_1 = 0;
    uint32_t len_2 = 0;
#ifdef _WIN32
    HANDLE stdin_handle;
    DWORD console_mode;
#endif
    int lines_printed = 0;
    char psw_yes = 0;
    int ret = 0;

    psw_1 = (char *)malloc(MAX_PSW_LEN + 1);
    psw_2 = (char *)malloc(MAX_PSW_LEN + 1);
    if (psw_1 == NULL || psw_2 == NULL) {
        free(psw_1);
        free(psw_2);
        return -1;
    }
    sodium_mlock(psw_1,MAX_PSW_LEN + 1);
    sodium_mlock(psw_2,MAX_PSW_LEN + 1);

    psw_1[MAX_PSW_LEN] = '\0';
    psw_2[MAX_PSW_LEN] = '\0';

    stdin_handle = GetStdHandle(STD_INPUT_HANDLE);

    //disable echo
#ifdef _WIN32
    GetConsoleMode(stdin_handle, &console_mode);
    console_mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(stdin_handle, console_mode);
#endif

    printf("Your password is not set.\nLet's create a new one!\nPlease enter your new password bellow:\n");
    fflush(stdout);
    lines_printed = 3;
    do{
        memset(psw_1, 0, MAX_PSW_LEN + 1);
        memset(psw_2, 0, MAX_PSW_LEN + 1);

#ifdef _WIN32
        ReadConsoleA(stdin_handle, psw_1, MAX_PSW_LEN + 1, (void*)&len_1, NULL);
#endif

        lines_printed++;
        psw_1[len_1-2] = '\0';
        while (!password_is_valid(psw_1)) {
            memset(psw_1, 0, MAX_PSW_LEN + 1);
            printf("\x1bM\x1b[2K\x1b[33mPassword contained non valid characters! Use only alpharithmetics and !@#$%%^&*_\nTry again:\n\x1b[39m");
            lines_printed +=2;
#ifdef _WIN32
            ReadConsoleA(stdin_handle, psw_1, MAX_PSW_LEN + 1, (void*)&len_1, NULL);
#endif
            psw_1[len_1-2] = '\0';
        }
        printf("Re-enter your password to verify it:");
        fflush(stdout);
#ifdef _WIN32
        ReadConsoleA(stdin_handle, psw_2, MAX_PSW_LEN + 1, (void*)&len_2, NULL);
#endif
        lines_printed++;
        psw_2[len_2-2] = '\0';
        if (memcmp(psw_1, psw_2, MAX_PSW_LEN) != 0) {
            delete_lines(lines_printed);
            printf("\x1b[33mPasswords did not match!\nPlease try again:\n\x1b[39m");
            lines_printed = 2;
        }
        else  psw_yes = 1;
    }while (!psw_yes);

    //enable echo again
#ifdef _WIN32
    console_mode |= ENABLE_ECHO_INPUT;
    SetConsoleMode(stdin_handle, console_mode);
#endif

    psw_1[MAX_PSW_LEN] = '\0';
    ret = save_password_hash(psw_1, strlen(psw_1));
    if (ret != INDIGO_SUCCESS) {
        free(psw_1);
        free(psw_2);
        return ret;
    }

    printf("\x1b[32m\nPassword created successfully!\n\x1b[39m");
#ifdef _WIN32
    Sleep(5000);
#endif
    delete_lines(lines_printed + 2);
    free(psw_1);
    free(psw_2);
    return INDIGO_SUCCESS;
}

int login(void **master_key) {
    char *psw;
    int lines_printed = 0;
    uint32_t len;
    int ret = 0;
#ifdef _WIN32
    HANDLE stdin_handle;
    DWORD console_mode;
#endif

    if (!password_hash_exists()) {
        if (!psw_salt_exists()) {
            ret = create_psw_salt(0);
            if (ret != INDIGO_SUCCESS) {
                return ret;
            }
        }
        if (!key_derivation_settings_exist()) {
            printf("Trying to set up password creation settings...\n");
            printf("Testing for optimal settings for your system.\n");
            printf("This might take several minutes\n");
            ret = create_key_derivation_settings();
            if (ret != INDIGO_SUCCESS) {
                return ret;
            }
            printf("\x1b[32mPassword creation settings created successfully.\x1b[39m\n");
#ifdef _WIN32
            Sleep(3000);
#endif
            delete_lines(4);
        }
        create_new_password();
    }

    //ask for user password and start the app
    psw = (char *)malloc(MAX_PSW_LEN + 1);
    if (psw == NULL) {
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    sodium_mlock(psw, MAX_PSW_LEN + 1);

    printf("Enter your password:\n");
    lines_printed = 1;
#ifdef _WIN32
    stdin_handle = GetStdHandle(STD_INPUT_HANDLE);

    //disable echo
    GetConsoleMode(stdin_handle, &console_mode);
    console_mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(stdin_handle, console_mode);

    ReadConsoleA(stdin_handle, psw, MAX_PSW_LEN + 1, (void*)&len, NULL);
    lines_printed++;
    psw[len-2] = '\0';
#endif
    ret = cmp_password_hash(psw, len-2);
    while (ret) {
        delete_lines(lines_printed);
        printf("\x1b[31mPassword is not valid. Please try again:\n\x1b[39m");
        lines_printed = 1;
#ifdef _WIN32
        ReadConsoleA(stdin_handle, psw, MAX_PSW_LEN + 1, (void*)&len, NULL);
        lines_printed++;
        psw[len-2] = '\0';
#endif
        ret = cmp_password_hash(psw, len-2);
    }
    //enable echo again
#ifdef _WIN32
    console_mode |= ENABLE_ECHO_INPUT;
    SetConsoleMode(stdin_handle, console_mode);
#endif
    printf("\x1b[32mLogin successful\n\x1b[39m");
#ifdef _WIN32
    Sleep(5000);
#endif
    delete_lines(lines_printed + 1);

    ret = derive_master_key(psw,len-2, master_key);
    if (ret != 0) {
        free(psw);
        return ret;
    }
    free(psw);
    return 0;
}