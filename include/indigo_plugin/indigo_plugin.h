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

#ifndef INDIGO_PLUGIN_H
#define INDIGO_PLUGIN_H
#include <stddef.h>
#include <indigo_plugin_interface.h>

#ifndef INDIGO_PLUGIN_VERSION
#define INDIGO_PLUGIN_VERSION (0x010101)
#endif

#ifndef INDIGO_PLUGIN_DIR
#define INDIGO_PLUGIN_DIR "plugins"
#endif
#ifndef INDIGO_USER_PLUGIN_DIR
#define INDIGO_USER_PLUGIN_DIR "config/user/plugins"
#endif

#define INDIGO_PLUGIN_GETTER_NAME "get_indigo_plugin"

typedef indigo_plugin_t *(*plugin_getter_fn)(void);

int load_plugin(char *path, indigo_plugin_t **plugin);
int load_plugin_now(char *path, indigo_plugin_t **plugin);
int load_plugins(indigo_plugin_t ***plugins, size_t *plugin_count);

int run_plugin(indigo_plugin_t *plugin);
int is_ui_plugin(indigo_plugin_t *plugin);

#endif // INDIGO_PLUGIN_H
