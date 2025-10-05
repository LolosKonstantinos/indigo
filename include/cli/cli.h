//
// Created by Constantin on 04/10/2025.
//


#include <stdio.h>
#include <sodium.h>
#include <ncurses/ncurses.h>

#ifndef CLI_H
#define CLI_H

int init_cli(void);

//todo: make it return via pointer the master key
int verify_password(void);

#endif //CLI_H
