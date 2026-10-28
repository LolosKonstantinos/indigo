/*Copyright (c) 2026 Lolos Konstantinos

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

#ifndef INDIGO_DIPLOMAT_H
#define INDIGO_DIPLOMAT_H

#define DIPLOMAT_OPTION_SHORT_FLAG  1
#define DIPLOMAT_OPTION_LONG_FLAG   2
#define DIPLOMAT_OPTION_FULL_FLAG   3
#define DIPLOMAT_OPTION_COMMAND     4

#define DIPLOMAT_OPTION_TYPE_BOOL   1
#define DIPLOMAT_OPTION_TYPE_INT    2
#define DIPLOMAT_OPTION_TYPE_FLOAT  3
#define DIPLOMAT_OPTION_TYPE_STRING 4

#define DIPLOMAT_RULE_DEPENDENT    1
#define DIPLOMAT_RULE_INCOMPLETE   2
#define DIPLOMAT_RULE_INCOMPATIBLE 3
#define DIPLOMAT_RULE_REQUIRED     4

#include <stddef.h>

typedef void(*diplomat_callback_fn)(void);

typedef struct diplomat_in_option_t {
    diplomat_callback_fn callback;
    char *option_help_text;
    char *option_long_name;
    char option_short_name;
    char input_type;
    char output_type;
    unsigned char zero[5];
}diplomat_in_option_t;

typedef struct diplomat_rule_t {
    char rule_type;

    char *option1_long_name;
    char option1_short_name;

    char *option2_long_name;
    char option2_short_name;
}diplomat_rule_t;

typedef union {
    double data_float;
    char *data_string;
    char data_bool;
    long long data_int;
}diplomat_out_flag_data_u;

typedef struct diplomat_out_option_t {
    char *opt_long_name;
    diplomat_out_flag_data_u data;
    char opt_short_name;
    char input_type;
    char output_type;
    unsigned char zero[5];
}diplomat_out_option_t;

diplomat_in_option_t *new_diplomat_option(char *option_text, char *long_name, char short_name, char input_type,
                                        char output_type,diplomat_callback_fn callback);
void free_diplomat_option(diplomat_in_option_t *option);

diplomat_rule_t *new_diplomat_rule(char rule_type, char *opt1_lname, char opt1_sname, char *opt2_lname, char opt2_sname);
void free_diplomat_rule(diplomat_rule_t *rule);

int diplomat_add_single_option(diplomat_in_option_t *option);
int diplomat_add_multiple_options(diplomat_in_option_t *options, size_t count);

int diplomat_add_single_rule(diplomat_rule_t *rule);
int diplomat_add_multiple_rules(diplomat_rule_t *rules, size_t count);

int diplomat_argue(int argc,char *const argv[], diplomat_out_option_t **options, size_t *count);

#endif // INDIGO_DIPLOMAT_H
