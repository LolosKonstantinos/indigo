//
// Created by Constantin on 04/10/2025.
//



#ifndef CLI_H
#define CLI_H
#include <ncurses/ncurses.h>

int init_cli(void);

//todo: make it return via pointer the master key
int verify_password(void);

WINDOW *create_welcome_screen();
int create_new_password();
#endif //CLI_H
