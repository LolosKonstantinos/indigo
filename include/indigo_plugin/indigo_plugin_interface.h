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

#ifndef INDIGO_INDIGO_PLUGIN_INTERFACE_H
#define INDIGO_INDIGO_PLUGIN_INTERFACE_H
/*
 * This header defines types that are needed for indigo to load, initialize, start and terminate,
 * a user defined plugin.
 *
 * An indigo plugin can define a thread that will run in parallel with the core indigo system
 * and managed by the indigo thread manager.
 * It can also define certain function that alter the behaviour of the core indigo processes.
 * Your plugin can define functions that will replace functions that the plugin manager will load,
 * and the indigo core will run instead of some other default function.
 * A plugin can define both. It can define both a thread and replacement functions.
 * A plugin CAN NOT define more than one thread.
 * If you need more than one thread, you need to create it inside the plugin thread
 * and manage it in the scope of the plugin.
 * If you need both threads to be managed by the indigo thread manager, you will need to create
 * 2 (two) separate plugins. Plugins are isolated by design, the indigo core does not support any
 * means for inter thread communication. That is not to say it is not possible. It is not supported
 * through functionalities of the indigo core.
 *
 *
 * The types indigo_plugin_args(number)_t are opaque structs that the plugin will define and
 * pointers to those structs will be supplied to functions that the indigo plugin and thread managers
 * will call.
 *
 * The indigo_thread_essential_args_t is a struct that contains 2 event flags.
 * This is only was your code can show its state to the indigo plugin and thread managers.
 * The thread manager will initialize these flags before creating the plugin thread.
 * You will need to use Functions defined in the event_flag.h header.
 *
 * Your plugin must define the following functions:
 * (1) int init(void)
 *     This function is the first function to be called in the plugin docking process.
 *     It should allocate and initialize any resources needed for the creation
 *     and safe deletion of the plugin thread.
 *     If your plugin does not need to do any of the above actions before creation,
 *     the function should still be defined and return 0;
 *     This function has a type of init_plugin_fn.
 *
 * (2) int destroy(indigo_plugin_args0_t * args)
 *     This function is the function called by the plugin manager or thread manager
 *     to terminate the operation of the present plugin and all operations, threads,
 *     processes it has started.
 *     This function can be called at any time and not just process termination.
 *     Before the calling of this function, the thread_flag will be signaled for termination.
 *     If it is not possible to set the flag, the thread manager will forcefully terminate
 *     the main thread of the plugin and will then proceed with a full application restart.
 *     This function should free all resources allocated by the plugin or associated with it
 *     and then fully terminate its operation
 *
 * Optional functions that can be defined:
 * (1) int * run(indigo_plugin_args2_t *args)
 *     This function is the function that will run in a separate thread.
 *     The args argument will be supplied by the indigo_plugin_args1 static variable.
 *     Therefore it should be initialized appropriately at plugin initialization.
 *
 * (2)
 */

typedef struct indigo_thread_essential_args_t indigo_plugin_thread_essential_args_t;

typedef struct indigo_plugin_thread_args_t {
    void *args;
    indigo_plugin_thread_essential_args_t *indigo_args;
} indigo_plugin_thread_args_t;

typedef int (*init_plugin_fn)(indigo_plugin_thread_essential_args_t *, indigo_plugin_thread_args_t **);
typedef int (*destroy_plugin_fn)(indigo_plugin_thread_args_t *);

typedef int *(*plugin_thread_fn)(indigo_plugin_thread_args_t *);

typedef int (*start_indigo_ui_fn)(void);

typedef struct indigo_plugin_t {
    const unsigned char version[8];
    init_plugin_fn init_plugin;
    destroy_plugin_fn destroy_plugin;
    plugin_thread_fn plugin_thread;
    start_indigo_ui_fn start_indigo_ui;
}indigo_plugin_t;

const indigo_plugin_t *get_indigo_plugin(void);

#endif // INDIGO_INDIGO_PLUGIN_INTERFACE_H
