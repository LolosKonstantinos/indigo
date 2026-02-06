//
// Created by Constantin on 04/10/2025.
//



#ifndef CLI_H
#define CLI_H
#define _XOPEN_SOURCE_EXTENDED
#include <ncursesw/curses.h>

int verify_user(void** master_key);

//todo: make it return via pointer the master key
int verify_password(void** master_key);

WINDOW *create_welcome_screen();
int create_new_password();
int iswspecialchar(wint_t ch);

int create_main_interface();
#endif //CLI_H
