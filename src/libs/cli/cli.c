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

#ifdef _WIN32
#include <windef.h>
#include <Winbase.h>
#include <WinCon.h>
#include <Winuser.h>
#ifndef CONSOLE_READ_NOWAIT
#define CONSOLE_READ_NOWAIT     0x0002
#endif
#else
/*assume Linux*/
#include <sys/ioctl.h>
#include <unistd.h>
#endif
#define FORCE_INLINE inline __attribute__((always_inline))

static const int command_count = 6;
static const char recognised_commands[6][64] = {
    "DEV",
    "DOC",
    "HELP",
    "FILES",
    "TRANSFER",
    "SETTINGS"
};
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
    for (int i = 0; i < count; i++) printf("\x1b[2K\x1bM");
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

    if (!signing_key_pair_exists()) {
        ret = create_signing_key_pair(*master_key);
        if (ret != INDIGO_SUCCESS) {
            return ret;
        }
    }

    return 0;
}

int create_main_loop(tree_t *device_tree, QUEUE *ui_queue) {
    QNODE *node = NULL;
    char in_key;
    int key_repeat_count = 0;
    char command[CHAR_MAX + 1];
    char command_len = 0;
    int command_num = 0;
    int ret = 0;
    int termination_flag = 0;
#ifdef _WIN32
    WIN_CONSOLE_INPUT ReadConsoleInputExA =
        (WIN_CONSOLE_INPUT)GetProcAddress(GetModuleHandle("kernel32.dll"), "ReadConsoleInputExA");
    if (ReadConsoleInputExA == NULL) {
        return INDIGO_ERROR_RESOURCE_NOT_FOUND;
    }
#endif


    while (!termination_flag) {
        //get queue events
        node = queue_pop(ui_queue, QOPT_NON_BLOCK);
        if (node) {
            switch (node->type) {
            case QET_TERMINATION:
                termination_flag = 1;
                break;
            default:
                break;
            }
            destroy_qnode(node);
            node = NULL;
        }

        //get user input
        #ifdef _WIN32
        ret = get_next_input(&in_key, 1, ReadConsoleInputExA);
        if (ret == -1) {
            break; //no idea what error this might be
        }
        key_repeat_count = ret;
        #else
        #endif
        if (key_repeat_count > 0){
            if (in_key == KEY_ENTER) {
                //execute the command
                command[CHAR_MAX] = '\0';
                //check if the command exists
                for (command_num = 0; command_num < command_count; command_num++) {
                    if (strcmp(recognised_commands[command_num], command) == 0)break;
                }
                if (command_num < command_count) {
                    command_len = 0;
                    command[0] = '\0';
                    //execute command with command number command_num
                }
                else {
                    //print error message
                }

            }
            else if (in_key == KEY_BACKSPACE) {

            }
            else if (is_special_key(in_key)) {

            }
            else {
                for (int i = 0; i < key_repeat_count; i++) {
                    if (command_len < CHAR_MAX) {
                        command[command_len] = in_key;
                        ++command_len;
                        command[command_len] = '\0';
                    }
                    else {
                        memmove(command, command + 1, CHAR_MAX - 1);
                        command[CHAR_MAX - 1] = in_key;
                        command[CHAR_MAX] = '\0';
                    }
                }
            }
        }

        //refresh ui
    }
}
int is_special_key(char key) {
    switch (key) {
    case KEY_ARROW_UP:
    case KEY_ARROW_DOWN:
    case KEY_ARROW_LEFT:
    case KEY_ARROW_RIGHT:
    case KEY_ENTER:
    case KEY_SPACE:
    case KEY_BACKSPACE:
    case KEY_TAB:
    case KEY_CTRL:
    case KEY_ALT:
    case KEY_SHIFT:
        return 1;
    default:
        return 0;
    }
}

#ifdef _WIN32
int get_next_input(char *input, char echo, WIN_CONSOLE_INPUT ReadConsoleInputExA) {
    int ret;
    INPUT_RECORD buf;
    int events_read;
    int repeat = 0;

    ret = ReadConsoleInputExA(GetStdHandle(STD_INPUT_HANDLE), &buf, sizeof(INPUT_RECORD), (void *)&events_read,CONSOLE_READ_NOWAIT);
    if (ret == 0) {
        return -1;
    }
    if (events_read == 0) {
        return 0;
    }
    if (buf.EventType == KEY_EVENT && buf.Event.KeyEvent.bKeyDown) {
        repeat = buf.Event.KeyEvent.wRepeatCount;
        switch (buf.Event.KeyEvent.wVirtualKeyCode) {
            //numbers 0-9
            case 0x30:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++)
                        putchar(')');
                }
                else {
                    for (int i = 0; i < repeat; i++)
                        putchar('0');
                }
            }
            break;
            case 0x31:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++)putchar('!');
                }
                else {
                    for (int i = 0; i < repeat; i++) putchar('1');}
            }
            break;
            case 0x32:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++)putchar('@');
                }
                else {
                    for (int i = 0; i < repeat; i++) putchar('2');
                }
            }
            break;
            case 0x33:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++) putchar('#');
                }
                else {
                    for (int i = 0; i < repeat; i++) putchar('3');
                }
            }
            break;
            case 0x34:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++) putchar('$');
                }
                else {
                    for (int i = 0; i < repeat; i++) putchar('4');
                }
            }
            break;
            case 0x35:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++) putchar('%');
                }
                else {
                    for (int i = 0; i < repeat; i++) putchar('5');
                }
            }
            break;
            case 0x36:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++) putchar('^');
                }
                else {
                    for (int i = 0; i < repeat; i++) putchar('6');
                }
            }
            break;
            case 0x37:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++) putchar('&');
                }
                else {
                    for (int i = 0; i < repeat; i++) putchar('7');
                }
            }
            break;
            case 0x38:
            *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
            if (echo) {
                if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                    for (int i = 0; i < repeat; i++) putchar('*');
                }
                else {
                    for (int i = 0; i < repeat; i++) putchar('8');
                }
            }
            break;
            case 0x39:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++) putchar('(');
                    }
                    else {
                        for (int i = 0; i < repeat; i++) putchar('9');
                    }
                }
                break;
            //letters A-Z
            case 0x41:
            case 0x42:
            case 0x43:
            case 0x44:
            case 0x45:
            case 0x46:
            case 0x47:
            case 0x48:
            case 0x49:
            case 0x4A:
            case 0x4B:
            case 0x4C:
            case 0x4D:
            case 0x4E:
            case 0x4F:
            case 0x50:
            case 0x51:
            case 0x52:
            case 0x53:
            case 0x54:
            case 0x55:
            case 0x56:
            case 0x57:
            case 0x58:
            case 0x59:
            case 0x5A:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (((buf.Event.KeyEvent.dwControlKeyState&CAPSLOCK_ON)>>3) ^
                         (buf.Event.KeyEvent.dwControlKeyState&SHIFT_PRESSED))
                    {
                        for (int i = 0; i < repeat; i++)
                            putchar(buf.Event.KeyEvent.wVirtualKeyCode);
                    }
                    else {
                        for (int i = 0; i < repeat; i++)
                            putchar(tolower(buf.Event.KeyEvent.wVirtualKeyCode));
                    }
                }
                break;
            case 0x25:
                *input = KEY_ARROW_LEFT;
                break;
            case 0x26:
                *input = KEY_ARROW_UP;
                break;
            case 0x27:
                *input = KEY_ARROW_RIGHT;
                break;
            case 0x28:
                *input = KEY_ARROW_DOWN;
                break;
            case 0x0D:
                *input = KEY_ENTER;
                break;
            case 0xA0:
            case 0xA1:
            case 0x10:
                *input = KEY_SHIFT;
                break;
            case 0x11:
            case 0xA2:
            case 0xA3:
                *input = KEY_CTRL;
                 break;
            case 0x12:
            case 0xA4:
            case 0xA5:
                *input = KEY_ALT;
                break;
            case 0x20:
                *input = KEY_SPACE;
                break;
            case 0x08:
                *input = KEY_BACKSPACE;
                break;
            case 0x09:
            *input = KEY_TAB;
            default:
            break;
        }
    }
    return repeat;
}
#endif