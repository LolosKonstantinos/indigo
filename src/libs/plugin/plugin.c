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
#include <stdlib.h>
#include <dlfcn.h>
#include "plugin.h"

int load_plugin(char *path, char **names, size_t name_count, char **symbols)
{
    void *handle = NULL;
    if (!path|| !names || !symbols|| name_count <= 0) {
        return -1;
    }

    handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        return -1;
    }

    for (int i = 0; i < name_count; i++) {
        symbols[i] = dlsym(handle, names[i]);
    }

    dlclose(handle);
    return 0;
}

int load_plugin_now(char *path, char **names, size_t name_count, char **symbols)
{
    void *handle = NULL;
    if (!path|| !names || !symbols|| name_count <= 0) {
        return -1;
    }

    handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        return -1;
    }

    for (int i = 0; i < name_count; i++) {
        symbols[i] = dlsym(handle, names[i]);
    }

    dlclose(handle);
    return 0;
}

int load_plugins(char **paths, size_t path_count, char **names, size_t name_count, void **symbols)
{
    void **handles = NULL;
    if (!paths || !names || !symbols|| path_count <= 0 || name_count <= 0) {
        return -1;
    }

    handles = malloc( path_count * sizeof(void *));
    if (!handles) {
        return -1;
    }
    //initialize the handles
    for (int i = 0; i < path_count; i++) {
        handles[i] = NULL;
    }

    //open the dynamic libs
    for (int i = 0; i < path_count; i++) {
        handles[i] = dlopen(names[i], RTLD_LAZY);

        if (!handles[i]) {
            for (int j = 0; i < path_count; j++) {
                if (handles[j]) dlclose(handles[j]);
            }
        }
    }

    //load the requested symbols
    for (int i = 0; i < name_count; i++) {
        symbols[i] = dlsym(handles[i], names[i]);
    }

    for (int i = 0; i < path_count; i++) {
        dlclose(handles[i]);
    }

    return 0;
}