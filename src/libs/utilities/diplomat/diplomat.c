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

#include "diplomat.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static diplomat_in_option_t *saved_options = NULL;
static size_t saved_options_count = 0;
static diplomat_rule_t *saved_rules = NULL;
static size_t saved_rule_count = 0;

diplomat_in_option_t *new_diplomat_option(char *option_text, char *long_name, char short_name, char input_type,
                                        char output_type,diplomat_callback_fn callback)
{
    diplomat_in_option_t *opt = malloc(sizeof(diplomat_in_option_t));
    if (!opt) {
        return NULL;
    }
    opt->option_help_text = strdup(option_text);
    opt->option_long_name = strdup(long_name);
    opt->option_short_name = short_name;
    opt->input_type = input_type;
    opt->output_type = output_type;
    opt->callback = callback;

    return opt;
}

void free_diplomat_option(diplomat_in_option_t *option)
{
    if (!option) {
        return;
    }
    free(option->option_help_text);
    free(option->option_long_name);
    free(option);
}
diplomat_rule_t *new_diplomat_rule(char rule_type, char *opt1_lname, char opt1_sname, char *opt2_lname, char opt2_sname)
{
    diplomat_rule_t *rule;
    if (!opt1_lname) {
        return NULL;
    }

    rule = malloc(sizeof(diplomat_rule_t));
    if (!rule) {
        return NULL;
    }
    rule->option1_long_name = strdup(opt1_lname);
    rule->option1_short_name = opt1_sname;

    if (opt2_lname) {
        rule->option2_long_name = strdup(opt2_lname);
    }
    else {
        rule->option2_long_name = NULL;
    }
    rule->option2_short_name = opt2_sname;

    return rule;
}
void free_diplomat_rule(diplomat_rule_t *rule)
{
    if (!rule) {
        return;
    }
    free(rule->option1_long_name);
    if (rule->option2_long_name) {
        free(rule->option2_long_name);
    }
    free(rule);
}

int diplomat_add_single_option(diplomat_in_option_t *option)
{
    void * tmp = NULL;
    if (!option) {
        return -1;
    }
    tmp = realloc(saved_options, saved_options_count + 1);
    if (!tmp) {
        return -1;
    }
    saved_options = tmp;
    saved_options[saved_options_count] = *option;
    ++saved_options_count;

    return 0;
}
int diplomat_add_multiple_options(diplomat_in_option_t *options, size_t count)
{
    if (!options) {
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        diplomat_add_single_option(options + i);
    }
    return 0;
}

int diplomat_add_single_rule(diplomat_rule_t *rule)
{
    void * tmp = NULL;
    if (!rule) {
        return -1;
    }
    tmp = realloc(saved_rules, saved_rule_count + 1);
    if (!tmp) {
        return -1;
    }
    saved_rules = tmp;
    saved_rules[saved_rule_count] = *rule;
    ++saved_rule_count;

    return 0;
}
int diplomat_add_multiple_rules(diplomat_rule_t *rules, size_t count)
{
    if (!rules) {
        return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        diplomat_add_single_rule(rules + i);
    }
    return 0;
}

static void init_diplomat_out_option(diplomat_out_option_t *out_option,diplomat_in_option_t *in_option, diplomat_out_flag_data_u flag_data)
{
    if (in_option->option_long_name)out_option->opt_long_name = strdup(in_option->option_long_name);
    else {
        out_option->opt_long_name = NULL;
    }
    out_option->opt_short_name = in_option->option_short_name;
    out_option->input_type = in_option->input_type;
    out_option->output_type = in_option->output_type;

    out_option->data = flag_data;
}

static void free_diplomat_out_option(diplomat_out_option_t *option)
{
    free(option->opt_long_name);
}

static char argument_type(char *arg)
{
    size_t len = strlen(arg);
    if (len < 2) {
        return -1;
    }

    if (len == 1 && arg[0] != '-') {
        return DIPLOMAT_OPTION_COMMAND;
    }

    if (arg[0] == '-' && arg[1] == '-') {
        return DIPLOMAT_OPTION_LONG_FLAG;
    }
    if (arg[0] == '-' && arg[1] != '-') {
        return DIPLOMAT_OPTION_SHORT_FLAG;
    }

    return DIPLOMAT_OPTION_COMMAND;
}

static diplomat_in_option_t *find_diplomat_in_option(char *long_name, char short_name)
{
    if (!long_name && short_name == '\0') return NULL;
    for (size_t i = 0; i < saved_options_count; ++i) {
        if (long_name) {
            if (strcmp(saved_options[i].option_long_name, long_name) == 0) {
                return &saved_options[i];
            }
        }

        if (short_name != '\0') {
            if (saved_options[i].option_short_name == short_name) {
                return &saved_options[i];
            }
        }
    }
    return NULL;
}

static int is_valid_non_bool_argument(char *arg)
{
    diplomat_in_option_t *input_option;
    char *equal_char_position;
    char type;
    size_t len = strlen(arg);

    type = argument_type(arg);
    if (type == -1) {
        return 0;
    }

    if (len < 4 && type == DIPLOMAT_OPTION_SHORT_FLAG) {
        equal_char_position = strchr(arg, '=');
        //there needs to be an equal sign in the option
        if (!equal_char_position) return 0;
        //check if there is a value after the equal sign
        if (equal_char_position == arg + len - 1) return 0;
        //check if the equal sign is not after the first flag
        //we don't allow multiple flags when at least one is not boolean
        if (equal_char_position != arg + 2) return 0;
    }

    if (len < 5 && type == DIPLOMAT_OPTION_LONG_FLAG) {
        equal_char_position = strchr(arg, '=');
        if (!equal_char_position) return 0;
        if (equal_char_position == arg + len - 1) return 0;
        if (equal_char_position == arg + 3) return 0;
    }

    //command arguments are always boolean
    if (type == DIPLOMAT_OPTION_COMMAND) return 0;

    return 1;
}

static int str_is_int(char *str)
{
    if (!str) return 0;
    if (*str == '-') str++;

    while (*str) {
        if (!isdigit(*str)) return 0;
        ++str;
    }
    return 1;
}
static int str_is_float(const char *str)
{
    char *ret;
    size_t len = strlen(str);
    if (len < 2) return 0;
    ret = strchr(str, '.');
    if (!ret) return 0;
    if (ret == str + len - 1) return 0;
    while (*str) {
        if (str != ret && !isdigit(*str)) return 0;
        ++str;
    }
    return 1;
}

int diplomat_argue(const int argc,char * const argv[], diplomat_out_option_t **options, size_t *count)
{
    int ret;
    char type;
    diplomat_out_flag_data_u data;
    diplomat_in_option_t *input_option;
    diplomat_out_option_t *output_options = NULL;
    size_t out_option_count = 0;
    size_t arg_len = 0;
    void *tmp = NULL;

    //extract flags from argument vector
    for (int i = 1; i < argc; ++i) {
        arg_len = strlen(argv[i]);
        type = argument_type(argv[i]);
        if (type == -1) continue;

        if (type == DIPLOMAT_OPTION_SHORT_FLAG) {
            for (size_t j = 1; j < arg_len; ++j) {
                input_option = find_diplomat_in_option(NULL, argv[i][j]);
                if (!input_option) goto cleanup;

                tmp = realloc(output_options, out_option_count + 1);
                if (!tmp) {
                    goto cleanup;
                }
                output_options = tmp;
                out_option_count += 1;

                if (input_option->input_type != DIPLOMAT_OPTION_TYPE_BOOL) {
                    char *data_ptr;
                    ret = is_valid_non_bool_argument(argv[i]);
                    if (!ret) goto cleanup;

                    data_ptr = strchr(argv[i], '=');
                    data_ptr += 1;

                    switch (input_option->input_type) {
                        case DIPLOMAT_OPTION_TYPE_FLOAT:
                            if (str_is_float(data_ptr)) {
                                data.data_float = strtod(data_ptr, NULL);
                                if (errno == ERANGE) goto cleanup;
                            }
                            else {
                                goto cleanup;
                            }
                            break;
                        case DIPLOMAT_OPTION_TYPE_INT:
                            if (str_is_int(data_ptr)) {
                                data.data_int = strtoll(data_ptr, NULL, 0);
                                if (errno == ERANGE) goto cleanup;
                            }
                            else {
                                goto cleanup;
                            }
                            break;
                        case DIPLOMAT_OPTION_TYPE_STRING:
                            data.data_string = strdup(data_ptr);
                            break;
                        default:
                            break;
                    }
                    init_diplomat_out_option(&output_options[out_option_count], input_option, data);

                    break;
                }

                data.data_bool = 1;
                init_diplomat_out_option(&output_options[out_option_count], input_option, data);
            }
        }
        else if (type == DIPLOMAT_OPTION_LONG_FLAG) {
            input_option = find_diplomat_in_option(argv[i]+2,'\0' );
            if (!input_option) goto cleanup;

            tmp = realloc(output_options, out_option_count + 1);
            if (!tmp) {
                goto cleanup;
            }
            output_options = tmp;
            out_option_count += 1;

            if (input_option->input_type != DIPLOMAT_OPTION_TYPE_BOOL) {
                char *data_ptr;
                ret = is_valid_non_bool_argument(argv[i]);
                if (!ret) goto cleanup;

                data_ptr = strchr(argv[i], '=');
                data_ptr += 1;

                switch (input_option->input_type) {
                    case DIPLOMAT_OPTION_TYPE_FLOAT:
                        if (str_is_float(data_ptr)) {
                            data.data_float = strtod(data_ptr, NULL);
                            if (errno == ERANGE) goto cleanup;
                        }
                        else {
                            goto cleanup;
                        }
                        break;
                    case DIPLOMAT_OPTION_TYPE_INT:
                        if (str_is_int(data_ptr)) {
                            data.data_int = strtoll(data_ptr, NULL, 0);
                            if (errno == ERANGE) goto cleanup;
                        }
                        else {
                            goto cleanup;
                        }
                        break;
                    case DIPLOMAT_OPTION_TYPE_STRING:
                        data.data_string = strdup(data_ptr);
                        break;
                    default:
                        break;
                }
                init_diplomat_out_option(&output_options[out_option_count], input_option, data);
            }
            else{
                data.data_bool = 1;
                init_diplomat_out_option(&output_options[out_option_count], input_option, data);
            }
        }
        else {
            input_option = find_diplomat_in_option(argv[i],'\0' );
            if (!input_option) goto cleanup;

            tmp = realloc(output_options, out_option_count + 1);
            if (!tmp) {
                goto cleanup;
            }
            output_options = tmp;
            out_option_count += 1;

            data.data_bool = 1;
            init_diplomat_out_option(&output_options[out_option_count], input_option, data);
        }
    }

    //check if the rules are applied

    for (uint64_t i = 0; i < out_option_count; ++i) {
        //check if the current option follows all rules
        for (size_t r = 1; r < saved_rule_count; ++r) {
            //check the current out option for all rules

            //check if the current rule applies to this option
            if (output_options[i].opt_long_name &&  saved_rules[r].option1_long_name) {
                if (strcmp(output_options[i].opt_long_name, saved_rules[r].option1_long_name) != 0) continue;
            }
            else if (output_options[i].opt_short_name != '\0' && saved_rules[r].option1_short_name != '\0') {
                if (output_options[i].opt_short_name != saved_rules[r].option1_short_name) continue;
            }
            else goto cleanup;

            switch (saved_rules[r].rule_type) {
                case DIPLOMAT_RULE_INCOMPATIBLE:
                    //check if the incompatible flag is in the list
                    for (size_t k = 1; k < out_option_count; ++k) {
                        if (saved_rules[r].option2_long_name) {
                            if (strcmp(output_options[k].opt_long_name, saved_rules[r].option2_long_name) == 0) {
                                goto cleanup;
                            }
                        }

                        if (saved_rules[r].option2_short_name != '\0') {
                            if (output_options[k].opt_short_name == saved_rules[r].option2_short_name) {
                                goto cleanup;
                            }
                        }
                    }
                    break;
                case DIPLOMAT_RULE_DEPENDENT: {
                    char found_dependency = 0;

                    //check if the dependence rule flag is in the list
                    for (size_t k = 1; k < out_option_count; ++k) {
                        if (saved_rules[r].option2_long_name) {
                            if (strcmp(output_options[k].opt_long_name, saved_rules[r].option2_long_name) == 0) {
                                found_dependency = 1;
                            }
                        }

                        if (saved_rules[r].option2_short_name != '\0') {
                            if (output_options[k].opt_short_name == saved_rules[r].option2_short_name) {
                                found_dependency = 1;
                            }
                        }
                    }

                    if (!found_dependency) goto cleanup;

                    break;
                }
                case DIPLOMAT_RULE_INCOMPLETE:{
                    char found_dependency = 0;

                    //we need to find an argument with dependency to this option

                    for (size_t k = 0; k < out_option_count; ++k) {
                        for (size_t l = 0; l < saved_rule_count; ++l) {
                            if (output_options[i].opt_long_name
                                &&output_options[k].opt_long_name
                                && saved_rules[l].option1_long_name)
                            {
                                if (strcmp(output_options[k].opt_long_name, saved_rules[l].option1_long_name) == 0
                                    && strcmp(output_options[i].opt_long_name, saved_rules[l].option2_long_name) == 0)
                                {
                                        found_dependency = 1;
                                }
                            }
                            else if (output_options[i].opt_short_name != '\0'
                                && output_options[k].opt_short_name != '\0'
                                && saved_rules[l].option1_short_name != '\0')
                            {
                                if (output_options[k].opt_short_name == saved_rules[l].option1_short_name
                                    && output_options[i].opt_short_name == saved_rules[l].option2_short_name)
                                {
                                    found_dependency = 1;
                                }
                            }
                            else goto cleanup;
                        }

                    }

                    if (!found_dependency) goto cleanup;

                    break;
                }
                default:
                    break;
            }
        }
    }

    //check if all required arguments are included
    {
        char found_dependency = 0;
        for (uint64_t i = 0; i < saved_rule_count; ++i) {
            if (saved_rules[i].rule_type != DIPLOMAT_RULE_REQUIRED) continue;

            for (size_t k = 1; k < out_option_count; ++k) {
                if (output_options[k].opt_long_name && saved_rules[i].option2_long_name) {
                    if (strcmp(output_options[k].opt_long_name, saved_rules[i].option2_long_name) == 0) {
                        found_dependency = 1;
                    }
                }

                if (output_options[k].opt_short_name != '\0' && saved_rules[i].option2_short_name != '\0') {
                    if (output_options[k].opt_short_name == saved_rules[i].option2_short_name) {
                        found_dependency = 1;
                    }
                }
            }
        }

        if (found_dependency == 0) goto cleanup;
    }

    //call any callbacks
    for (size_t k = 1; k < out_option_count; ++k) {
        input_option = find_diplomat_in_option(output_options[k].opt_long_name, output_options[k].opt_short_name);
        if (input_option == NULL) goto cleanup;

        if (input_option->callback) input_option->callback();
    }

    return 0;

    cleanup:

    for (size_t i = 0; i < out_option_count; ++i) {
        free_diplomat_out_option(&output_options[i]);
    }
    free(output_options);
    *options = NULL;
    *count = 0;
    return -1;
}
