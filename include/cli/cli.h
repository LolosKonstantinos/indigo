//
// Created by Constantin on 04/10/2025.
//



#ifndef CLI_H
#define CLI_H
#define _XOPEN_SOURCE_EXTENDED
#include <ncursesw/curses.h>

int verify_user(void);

//todo: make it return via pointer the master key
int verify_password(void);

WINDOW *create_welcome_screen();
int create_new_password();
int iswspecialchar(wint_t ch);
#endif //CLI_H
