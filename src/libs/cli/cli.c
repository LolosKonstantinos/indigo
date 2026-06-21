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
#include "indigo_errors.h"
#include "indigo_types.h"
#include <cli.h>
#include <crypto_utils.h>
#include <ctype.h>
#include <dirent.h>
#include <glib-2.0/glib.h>
#include <glib-2.0/glib/gprintf.h>
#include <glib-2.0/glib/gstdio.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <uchar.h>
#include <wctype.h>

#ifdef _WIN32
#include <WinCon.h>
#include <Winbase.h>
#include <Winuser.h>
#include <windef.h>
#ifndef CONSOLE_READ_NOWAIT
#define CONSOLE_READ_NOWAIT 0x0002
#endif
#else
/*assume Linux*/
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <wchar.h>
#endif

#define FORCE_INLINE inline __attribute__((always_inline))

static const int chc_command_count = 7;
static const char chc_commands[8][64] = {"DEVICES",  "FILES",           "HELP",   "NONE", "INCOMING",
                                         "SETTINGS", "TRUSTED DEVICES", "REFRESH"};
static const char devices_commands[1][64] = {"SEND"};
static const char files_commands[4][64] = {"STOP", "CONTINUE", "RESUME", "CANCEL"};
static const char incomming_commands[4][64] = {"YES", "ACCEPT", "NO", "DENY"};
static const char trusted_devices_commands[4][64] = {"TRUST", "IS SUS", "UNTRUST", "UTRUST"};

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

    if (rows)
        *rows = info.dwSize.Y;
    if (cols)
        *cols = info.dwSize.X;
#else
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    if (rows)
        *rows = w.ws_row;
    if (cols)
        *cols = w.ws_col;
#endif
    return 0;
}

FORCE_INLINE void clear_screen() { printf("\x1B[2J\x1B[H"); }

FORCE_INLINE void delete_lines(const int count) {
    for (int i = 0; i < count; i++)
        printf("\x1b[2K\x1bM");
}

int new_progress_bar(progress_bar_t **progress_bar) {
    progress_bar_t *new_progress_bar = malloc(sizeof(progress_bar_t));
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
    if (!progress_bar)
        return -1;
    progress_bar->percentage = progress;
    return 0;
}
int move_progress_bar(progress_bar_t *progress_bar, int x, int y) {
    if (!progress_bar)
        return -1;
    progress_bar->x = x;
    progress_bar->y = y;
    return 0;
}
int refresh_progress_bar(progress_bar_t *progress_bar) {
    char move[32] = "\x1b[";
    int char_count;
    if (!progress_bar)
        return -1;

    char_count = ((progress_bar->width - 2) * progress_bar->percentage) / 100;

    // prepare the string to move to the position of the progress bar
    sprintf(move + 5, "%d", progress_bar->y);
    strcat(move, "};{");
    sprintf(move + strlen(move), "%d", progress_bar->x);
    strcat(move, "}H");

    // save the cursor position
    printf("\277");
    // move to the progress bar
    move[31] = '\0'; // for safety, I don't think anything could happen
    printf("%s", move);

    putchar('[');

    for (int i = 0; i < char_count; i++)
        putchar('#');
    for (int i = 0; i < progress_bar->width - 2 - char_count; i++)
        putchar(' ');

    putchar(']');

    // move to the saved cursor position
    printf("\278");
    return 0;
}

// login utils
void bypass_login(void **master_key) { derive_master_key("test", 4, master_key); }

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
    if (!psw)
        return 0;

    psw[MAX_PSW_LEN] = '\0';

    for (int i = 0; i < MAX_PSW_LEN; i++) {
        if (psw[i] == '\0')
            break;
        if (psw[i] & (1 << 7))
            return 0;
        if (!(isalnum(psw[i]) || isspecialchar(psw[i])))
            return 0;
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
    sodium_mlock(psw_1, MAX_PSW_LEN + 1);
    sodium_mlock(psw_2, MAX_PSW_LEN + 1);

    psw_1[MAX_PSW_LEN] = '\0';
    psw_2[MAX_PSW_LEN] = '\0';

#ifdef _WIN32
    stdin_handle = GetStdHandle(STD_INPUT_HANDLE);

    // disable echo
    GetConsoleMode(stdin_handle, &console_mode);
    console_mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(stdin_handle, console_mode);
#endif

    printf("Your password is not set.\nLet's create a new one!\nPlease enter "
           "your new password bellow:\n");
    fflush(stdout);
    lines_printed = 3;
    do {
        memset(psw_1, 0, MAX_PSW_LEN + 1);
        memset(psw_2, 0, MAX_PSW_LEN + 1);

#ifdef _WIN32
        ReadConsoleA(stdin_handle, psw_1, MAX_PSW_LEN + 1, (void *)&len_1, NULL);
#endif

        lines_printed++;
        psw_1[len_1 - 2] = '\0';
        while (!password_is_valid(psw_1)) {
            memset(psw_1, 0, MAX_PSW_LEN + 1);
            printf("\x1bM\x1b[2K\x1b[33mPassword contained non valid characters! Use "
                   "only alpharithmetics and !@#$%%^&*_\nTry again:\n\x1b[39m");
            lines_printed += 2;
#ifdef _WIN32
            ReadConsoleA(stdin_handle, psw_1, MAX_PSW_LEN + 1, (void *)&len_1, NULL);
#endif
            psw_1[len_1 - 2] = '\0';
        }
        printf("Re-enter your password to verify it:");
        fflush(stdout);
#ifdef _WIN32
        ReadConsoleA(stdin_handle, psw_2, MAX_PSW_LEN + 1, (void *)&len_2, NULL);
#endif
        lines_printed++;
        psw_2[len_2 - 2] = '\0';
        if (memcmp(psw_1, psw_2, MAX_PSW_LEN) != 0) {
            delete_lines(lines_printed);
            printf("\x1b[33mPasswords did not match!\nPlease try again:\n\x1b[39m");
            lines_printed = 2;
        } else
            psw_yes = 1;
    } while (!psw_yes);

    // enable echo again
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

    // ask for user password and start the app
    psw = (char *)malloc(MAX_PSW_LEN + 1);
    if (psw == NULL) {
        return INDIGO_ERROR_NOT_ENOUGH_MEMORY_ERROR;
    }
    sodium_mlock(psw, MAX_PSW_LEN + 1);

    printf("Enter your password:\n");
    lines_printed = 1;
#ifdef _WIN32
    stdin_handle = GetStdHandle(STD_INPUT_HANDLE);

    // disable echo
    GetConsoleMode(stdin_handle, &console_mode);
    console_mode &= ~ENABLE_ECHO_INPUT;
    SetConsoleMode(stdin_handle, console_mode);

    ReadConsoleA(stdin_handle, psw, MAX_PSW_LEN + 1, (void *)&len, NULL);
    lines_printed++;
    psw[len - 2] = '\0';
#endif
    ret = cmp_password_hash(psw, len - 2);
    while (ret) {
        delete_lines(lines_printed);
        printf("\x1b[31mPassword is not valid. Please try again:\n\x1b[39m");
        lines_printed = 1;
#ifdef _WIN32
        ReadConsoleA(stdin_handle, psw, MAX_PSW_LEN + 1, (void *)&len, NULL);
        lines_printed++;
        psw[len - 2] = '\0';
#endif
        ret = cmp_password_hash(psw, len - 2);
    }
    // enable echo again
#ifdef _WIN32
    console_mode |= ENABLE_ECHO_INPUT;
    SetConsoleMode(stdin_handle, console_mode);
#endif
    printf("\x1b[32mLogin successful\n\x1b[39m");
#ifdef _WIN32
    Sleep(5000);
#endif
    delete_lines(lines_printed + 1);

    ret = derive_master_key(psw, len - 2, master_key);
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
    uint64_t in_key;
    int key_repeat_count = 0;
    char command[sizeof(uint32_t) * (CHAR_MAX + 1)];
    char command_len = 0;
    int command_num = 0;
    int lines_printed = 0;
    unsigned char **id_array = NULL;
    char context = INDIGO_CLI_CONTEXT_NONE;
    int ret = 0;
    int termination_flag = 0;

    // print the notification line (it exists in every context)
    printf("\x1b[2;33m[!]There are currently no notifications\x1b[22;39m\n");
    // print the prompt prefix (or whatever this thing is called)
    printf("Indigo>");
    lines_printed = 1;

    // the main loop
    while (!termination_flag) {
        // get queue events
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

        // refresh ui
        switch (command_num) {
            case 0: // devises
                delete_lines(lines_printed - 1);
                lines_printed = 1;
                context = INDIGO_CLI_CONTEXT_DEV_LIST;
                print_devises(device_tree, &lines_printed, &id_array);
                printf("\nIndigo>");
                ++lines_printed;
                break;
            case 1: // files
                context = INDIGO_CLI_CONTEXT_ACTIVE_FILES;
                break;
            case 2: // help
                context = INDIGO_CLI_CONTEXT_HELP;
                break;
            case 3: // none
                context = INDIGO_CLI_CONTEXT_NONE;
                break;
            case 4: // incoming requests
                context = INDIGO_CLI_CONTEXT_INCOMING_FILES;
                break;
            case 5: // settings
                context = INDIGO_CLI_CONTEXT_SETTINGS;
                break;
            case 6: /// trusted devises
                context = INDIGO_CLI_CONTEXT_TRUSTED_DEVICES;
                break;
            default:
                break;
        }

        // get user input
        ret = get_next_char(&in_key);
        if (ret == -1) {
            break; // no idea what error this might be
        }
        key_repeat_count = ret;

        if (key_repeat_count > 0) {
            if (in_key == KEY_ENTER) {
                // execute the command
                command[sizeof(uint32_t) * (CHAR_MAX + 1) - 1] = '\0';
                // TODO: remove extra spaces
                // TODO: tokenize and capitalize the first token
                // the only time we dont want to capitalize everything is when we have a path

                // check if the command exists
                for (command_num = 0; command_num < chc_command_count; command_num++) {
                    // TODO: we use utf8, this will now work
                    if (strcmp(chc_commands[command_num], command) == 0)
                        break;
                }

                if (command_num < chc_command_count) {
                    command_len = 0;
                    command[0] = '\0';
                    // delete all content and print the notification line and the action
                    // content if needed (only if the content doesn't need to be updated)
                    delete_lines(lines_printed);
                    // print the notification line (it exists in every context)
                    printf("\x1b[2;33m[!]There are currently no notifications\x1b[22;39m\n");
                    // print the prompt prefix (or whatever this thing is called)
                    // TODO: print the content for each context
                    switch (command_num) {
                        case 0: // devises
                            context = INDIGO_CLI_CONTEXT_DEV_LIST;
                            print_devises(device_tree, &lines_printed, &id_array);
                            break;
                        case 1: // files
                            context = INDIGO_CLI_CONTEXT_ACTIVE_FILES;
                            break;
                        case 2: // help
                            context = INDIGO_CLI_CONTEXT_HELP;
                            break;
                        case 3: // none
                            context = INDIGO_CLI_CONTEXT_NONE;
                            break;
                        case 4: // incoming requests
                            context = INDIGO_CLI_CONTEXT_INCOMING_FILES;
                            break;
                        case 5: // settings
                            context = INDIGO_CLI_CONTEXT_SETTINGS;
                            break;
                        case 6: /// trusted devises
                            context = INDIGO_CLI_CONTEXT_TRUSTED_DEVICES;
                            break;
                        default:
                            break;
                    }
                    printf("Indigo>");
                    lines_printed = 1;
                } else {
                    // check if it is a subcommand of the current context
                    // print error messages
                    command_len = 0;
                    command[0] = '\0';
                    printf("\n\x1b[31mThis is not a valid command.\x1b\n\x1b[39mIndigo>");
                    lines_printed += 2;
                }

            } else if (in_key == KEY_BACKSPACE) {
                // delete characters form the user input
                for (int i = 0; i < command_len || i < key_repeat_count; i++) {
                    *((char *)(g_utf8_offset_to_pointer(command, -1))) = '\0';
                    --command_len;
                    // delete the whole user input and print the last 64 characters of the
                    // command
                    printf("\x1b[2KIndigo>"); // delete the line and print Indigo
                    if (command_len <= 64)
                        g_printf("%s", command);
                    else
                        g_printf("%s", g_utf8_offset_to_pointer(command, command_len - 63));
                }
            } else if (is_special_key(in_key)) {
                // do nothing for now
            } else {
                // it is a character, we add it to the command
                for (int i = 0; i < key_repeat_count; i++) {
                    if (command_len < CHAR_MAX) {
                        strcat(command, (char *)&in_key);
                        ++command_len;
                    }
                }
            }
        }
    }
    return 0;
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
// returns via pointer the key that was pressed
int get_next_key(char *input) {
    int ret;
    INPUT_RECORD buf;
    int events_read;
    int repeat = 0;

    ret = ReadConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), &buf, 1, (void *)&events_read);
    if (ret == 0) {
        return -1;
    }
    if (events_read == 0) {
        return 0;
    }
    if (buf.EventType == KEY_EVENT && buf.Event.KeyEvent.bKeyDown) {
        repeat = buf.Event.KeyEvent.wRepeatCount;
        switch (buf.Event.KeyEvent.wVirtualKeyCode) {
            // numbers 0-9
            case 0x30:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar(')');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('0');
                    }
                }
                break;
            case 0x31:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('!');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('1');
                    }
                }
                break;
            case 0x32:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('@');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('2');
                    }
                }
                break;
            case 0x33:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('#');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('3');
                    }
                }
                break;
            case 0x34:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('$');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('4');
                    }
                }
                break;
            case 0x35:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('%');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('5');
                    }
                }
                break;
            case 0x36:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('^');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('6');
                    }
                }
                break;
            case 0x37:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('&');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('7');
                    }
                }
                break;
            case 0x38:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('*');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('8');
                    }
                }
                break;
            case 0x39:
                *input = (char)buf.Event.KeyEvent.wVirtualKeyCode;
                if (echo) {
                    if (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED) {
                        for (int i = 0; i < repeat; i++)
                            putchar('(');
                    } else {
                        for (int i = 0; i < repeat; i++)
                            putchar('9');
                    }
                }
                break;
            // letters A-Z
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
                    if (((buf.Event.KeyEvent.dwControlKeyState & CAPSLOCK_ON) >> 3) ^
                        (buf.Event.KeyEvent.dwControlKeyState & SHIFT_PRESSED)) {
                        for (int i = 0; i < repeat; i++)
                            putchar(buf.Event.KeyEvent.wVirtualKeyCode);
                    } else {
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

// returns via pointer the character that was typed, includes control keys
int get_next_char(utf8_char_t *input) {
    int ret;
    size_t lret;
    mbstate_t mb_state = {0};
#ifdef _WIN32
    HANDLE console;
    INPUT_RECORD rec;
    DWORD rec_num;
    DWORD dret;
    WCHAR character = 0;
    int character_count = 0;
    disable_line_input();

    console = GetStdHandle(STD_INPUT_HANDLE);

    *input = 0; // make sure that we write to a clean buffer

    // get the next utf16 chunk
    ret = ReadConsoleInputW(console, &rec, 1, &rec_num);
    if (ret == 0)
        return -1;
    if (rec_num == 0)
        return 0;

    // we want it to be a key event (basically we want characters) and we choose
    // to only care when the key is pressed
    if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown == TRUE) {
        // check for control key presses (ctrl, alt, del, shift, etc.)
        *input = 0;
        switch (rec.Event.KeyEvent.wVirtualKeyCode) {
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
                break;
            case 0x2E:
                *input = KEY_DELETE;
                break;
            case 0x1B:
                *input = KEY_ESC;
                break;
            default:
                break;
        }

        // check if we actually got a control event
        // returns <-1. the caller knows that it's a control char and how many times
        // it was pressed if needed
        if (*input != 0)
            return (-1) - (rec.Event.KeyEvent.wRepeatCount);

        // copy the utf16 chunk (could be the first part of a 4byte character or
        // just a character)
        character = rec.Event.KeyEvent.uChar.UnicodeChar;
        character_count = rec.Event.KeyEvent.wRepeatCount;
        // we may get 0 if some control key that we don't care about is pressed
        if (character == 0)
            return 0;

        // convert the utf16 character to utf8 (
        lret = c16rtomb((char *)input, character, &mb_state);
        switch (lret) {
            case (size_t)-1:
                return -1;
            case 0:
                // we need the next surrogate pair
                //  get the next part (the next record may just be the previous but with
                //  key up) we loop until we get the next key down key event
                while (1) {
                    // wait until there is a record to read
                    dret = WaitForSingleObject(console, 69);
                    if (dret != WAIT_OBJECT_0)
                        return -1;

                    ret = PeekConsoleInputW(console, &rec, 1, &rec_num);
                    if (ret == 0)
                        return -1;
                    // check if it is a key event and is key pressed and then copy the
                    // character
                    if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown == TRUE) {
                        // copy the second part of the character
                        character = rec.Event.KeyEvent.uChar.UnicodeChar;
                        // if the second part is not valid per utf16 we leave with an error
                        if (character < 0xdc00 || character > 0xdfff)
                            return -1;
                        // remove the event since we can use it
                        ReadConsoleInputW(console, &rec, 1, &rec_num);
                        lret = c16rtomb((char *)input, character, &mb_state);
                        if (lret == (size_t)-1)
                            return -1;

                        break;
                    }

                    // it was an event we don't care about so we remove it
                    ReadConsoleInputW(console, &rec, 1, &rec_num);
                }
                break;
            default:
                if (lret > 4) {
                    *input = 0;
                    return -1;
                }
                break;
        }
    } else
        return 0;

    return character_count;
#else
    // assume linux
    struct termios termios;
    struct termios term_initial;
    wint_t c = 0;

    *input = 0;
    ret = tcgetattr(STDIN_FILENO, &term_initial);
    termios = term_initial;
    cfmakeraw(&termios);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios);
    setvbuf(stdin, NULL, _IONBF, 0);

    c = fgetwc(stdin);
    if (c == WEOF) {
        // this is either an error or no 0 characters
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_initial);
        return 0;
    }
    switch (c) {
        case L'\x1b':
            *input = KEY_ESC;
            break;
        case L'\n':
        case L'\r':
            *input = KEY_ENTER;
            break;
        case L'\b':
        case L'\x7f':
            *input = KEY_BACKSPACE;
            break;
        default:
            break;
    }
    if (*input != 0) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_initial);
        return -2;
    }

    wcrtomb((char *)input, c, &mb_state);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_initial);
    return 1;
#endif
}

int echo() {
#ifdef _WIN32
    DWORD mode;
    GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
    mode |= (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
    return 0;
#endif
    return 0;
}
int no_echo() {
#ifdef _WIN32
    DWORD mode;
    GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
    mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
    return 0;
#endif
    return 0;
}
int enable_line_input() {
#ifdef _WIN32
    DWORD mode;
    GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
    mode |= ENABLE_LINE_INPUT;
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
    return 0;
#endif
    return 0;
}
int disable_line_input() {
#ifdef _WIN32
    DWORD mode;
    GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
    mode &= ~ENABLE_LINE_INPUT;
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
    return 0;
#endif
    return 0;
}

int print_devises(tree_t *device_tree, int *lines_printed, unsigned char ***id_array) {
    // this function does not clear space above the cursor.
    // if this function is used to update the tree page make sure you have cleared
    // the previous screen first.
    tree_iterator_t *iterator;
    remote_device_t *remote_device;
    unsigned char **tmp_id_array = NULL;
    void *tmp = NULL;
    uint64_t i = 0;
    int ret = 0;
    // check if the pointers exist
    if (!(device_tree && lines_printed)) {
        return -1;
    }
    // create a tree iterator
    ret = new_tree_iterator(device_tree, &iterator);
    if (ret)
        return ret;
    // iterate through the tree and print devises
    while (tree_has_next(iterator)) {
        // allocate one more id
        tmp = realloc(tmp_id_array, (i + 1) * sizeof(unsigned char *));
        if (!tmp)
            goto cleanup;

        tmp_id_array = tmp;
        tmp_id_array[i] = NULL;

        tmp = malloc(crypto_sign_PUBLICKEYBYTES);
        if (!tmp)
            goto cleanup;

        tmp_id_array[i] = tmp;

        // get the next remote device
        tree_next(iterator, (void **)&remote_device);
        // add the id to the array
        memcpy(tmp_id_array[i], remote_device->peer_pk, crypto_sign_PUBLICKEYBYTES);
        // print the device info
        printf("dev_%llu \t: %ls\n", (unsigned long long)i, remote_device->username);
        // print the hex id of the devise
        for (int i = 0; i < 32; i++) {
            printf("%02x", (remote_device->peer_pk)[i]);
        }
        putchar('\n');
        // update counters
        (*lines_printed) += 2;
        ++i;
    }
    *id_array = tmp_id_array;
    return 0;
cleanup:
    if (tmp_id_array) {
        for (uint64_t j = 0; j < i; j++) {
            free(tmp_id_array[j]);
        }
        free(tmp_id_array);
    }
    *id_array = NULL;
    return -1;
}

// select a path
// TODO: print the cwd path so the user knows where they are
int pathfinder(char path[PATH_MAX * sizeof(utf8_char_t)]) {
    int lines_printed = 0;
    utf8_char_t in_char;
    int key_repeat_count = 0;
    uint64_t character_len = 0;
    char in_path[sizeof(uint32_t) * PATH_MAX];
    int in_path_len = 0;
    int ret = 0;
    GDir *curr_dir = NULL;
    GError *err = NULL;
    GStatBuf stat_buf;
    const char *dir_entry = NULL;
    char *cpath = NULL;
    char *cwd = NULL;

    // print the cwd and print help on top
    printf(
        "\n\x1b[2mEnter . to select the cwd, or a filename to select the respective file. Use ESC to quit.\x1b[22m\n");
    lines_printed = 2;
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
            return -1;
        }
        ret = g_file_test(cpath, G_FILE_TEST_EXISTS);
        if (ret == 0)
            continue;
        ret = g_file_test(cpath, G_FILE_TEST_IS_DIR);
        if (ret) {
            // if it is a directory print it in blue
            g_printf("\x1b[34;1m%s\x1b[39;22m\n", dir_entry);
        } else {
            // if it is a file or symlink print it in green
            g_printf("\x1b[34;1m%s\x1b[39;22m\n", dir_entry);
        }
        g_free(cpath);
        cpath = NULL;
        ++lines_printed;
    }
    g_dir_close(curr_dir);
    printf("Indigo>");

    while (1) {
        // get user input
        ret = get_next_char(&in_char);
        if (ret == -1) {
            break; // no idea what error this might be
        }
        key_repeat_count = ret;
        in_char &= 0xffffffff00000000;

        if (key_repeat_count > 0) {
            // it is a character, we add it to the command
            for (int i = 0; i < key_repeat_count; i++) {
                if (in_path_len < PATH_MAX) {
                    strcat(in_path, (char *)&in_char);
                    ++in_path_len;
                }
            }
            printf("\x1b[2KIndigo>"); // delete the line and print Indigo
            if (in_path_len <= 64)
                g_printf("%s", in_path);
            else
                g_printf("%s", in_path + in_path_len - 63);
        } else if (ret < -1) {
            // it is a control key
            if (in_char == KEY_ESC) {
                // free resources and exit with
                memset(path, 0, PATH_MAX * sizeof(utf8_char_t));
                return 1;
            }
            if (in_char == KEY_ENTER) {
                // we support full paths
                // we support relative paths
                // enter goes to the path
                // if the path is "." we select the current path
                // todo: use tab to autocomplete
                cpath = g_canonicalize_filename(in_path, NULL);
                if (!cpath) {
                    return -1;
                }

                // check if the user entered the current path to select it
                cwd = g_get_current_dir();
                if (strcmp(cwd, cpath) == 0) {
                    g_utf8_strncpy(path, cpath, PATH_MAX);
                    g_free(cwd);
                    g_free(cpath);
                    return 0;
                }
                g_free(cwd);

                // check if the file exists
                if (g_file_test(cpath, G_FILE_TEST_EXISTS)) {
                    // either path is a file, or path is invalid.
                    //  the path is not valid or cannot be g_access
                    //  print error and Re-enter
                    printf("\x1b[2K\x1b[31mEntered path is not valid! Try again!\x1b[39\nIndigo>");
                    ++lines_printed;
                    in_path_len = 0;
                    memset(in_path, 0, sizeof(uint32_t) * PATH_MAX);
                    g_free(cpath);
                    cpath = NULL;
                    continue;
                }

                if (g_file_test(cpath, G_FILE_TEST_IS_REGULAR)) {
                    // we just select the file
                    g_utf8_strncpy(path, cpath, PATH_MAX - 1);
                    return 0;
                }
                if (g_chdir(cpath)) {
                    // either path is a file, or path is invalid.
                    //  the path is not valid or cannot be g_access
                    //  print error and Re-enter
                    printf("\x1b[2K\x1b[31mEntered path is not valid! Try again!\x1b[39\nIndigo>");
                    ++lines_printed;
                    in_path_len = 0;
                    memset(in_path, 0, sizeof(uint32_t) * PATH_MAX);
                    g_free(cpath);
                    cpath = NULL;
                    continue;
                }

                g_free(cpath);
                cpath = NULL;

                curr_dir = g_dir_open(".", 0, &err);
                if (err) {
                    // TODO: check error codes, we don't want to print plain errors. error handle bbetter
                    g_printerr("%s", err->message);
                    g_clear_error(&err);
                }
                // print the current directory
                delete_lines(lines_printed);
                printf("\n\x1b[2mEnter . to select the cwd, or a filename to select the respective file. Use ESC to "
                       "quit.\x1b[22m\n");
                lines_printed = 2;

                dir_entry = g_dir_read_name(curr_dir);
                while (dir_entry) {
                    cpath = g_canonicalize_filename(dir_entry, NULL);
                    if (!cpath) {
                        g_dir_close(curr_dir);
                        return -1;
                    }
                    ret = g_file_test(cpath, G_FILE_TEST_EXISTS);
                    if (ret == 0)
                        continue;
                    ret = g_file_test(cpath, G_FILE_TEST_IS_DIR);
                    if (ret) {
                        // if it is a directory print it in blue
                        g_printf("\x1b[34;1m%s\x1b[39;22m\n", dir_entry);
                    } else {
                        // if it is a file or symlink print it in green
                        g_printf("\x1b[34;1m%s\x1b[39;22m\n", dir_entry);
                    }
                    g_free(cpath);
                    cpath = NULL;
                    ++lines_printed;
                }
                g_dir_close(curr_dir);
                printf("Indigo>");

            } else if (in_char == KEY_BACKSPACE) {
                // delete characters form the user input
                for (int i = 0; i < in_path_len || i < key_repeat_count; i++) {
                    // delete the last character
                    *((char *)(g_utf8_offset_to_pointer(in_path, -1))) = '\0';
                    --in_path_len;
                    // delete the whole user input and print the last 64 characters of the
                    // command
                    printf("\x1b[2KIndigo>"); // delete the line and print Indigo
                    if (in_path_len <= 64)
                        g_printf("%s", in_path);
                    else
                        g_printf("%s", in_path + in_path_len - 63);
                }
            }
        }
    }
    return 0;
}
