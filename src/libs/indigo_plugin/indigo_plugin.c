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
#include "indigo_plugin.h"

#include <glib-2.0/glib.h>
#include <glib-2.0/glib/gstdio.h>
#include <gmodule.h>
#include <limits.h>
#include <config.h>

int load_plugin(char *path, indigo_plugin_t **plugin)
{
    void *handle = NULL;
    plugin_getter_fn plugin_getter = NULL;
    if (!path) {
        return -1;
    }

    handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        return -1;
    }

    plugin_getter = dlsym(handle, INDIGO_PLUGIN_GETTER_NAME);
    if (!plugin_getter) {
        dlclose(handle);
        return -1;
    }

    dlclose(handle);

    *plugin = plugin_getter();

    if (!plugin) {
        return -1;
    }

    if ((*plugin)->init_plugin == NULL || (*plugin)->destroy_plugin == NULL) {
        *plugin = NULL;
        return -1;
    }


    return 0;
}

int load_plugin_now(char *path, indigo_plugin_t **plugin)
{
    void *handle = NULL;
    plugin_getter_fn plugin_getter = NULL;
    if (!path) {
        return -1;
    }

    handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        return -1;
    }

    plugin_getter = dlsym(handle, INDIGO_PLUGIN_GETTER_NAME);
    if (!plugin_getter) {
        dlclose(handle);
        return -1;
    }

    dlclose(handle);

    *plugin = plugin_getter();

    if (!plugin) {
        return -1;
    }

    if ((*plugin)->init_plugin == NULL || (*plugin)->destroy_plugin == NULL) {
        *plugin = NULL;
        return -1;
    }


    return 0;
}

int load_plugins(indigo_plugin_t ***plugins, size_t *plugin_count)
{
    char plugin_dir_path[PATH_MAX] = {0};
    int ret = 0;
    GDir *plugin_dir = NULL;
    GError *err = NULL;
    const char *dir_entry = NULL;
    char *cpath = NULL;
    indigo_plugin_t **plugin_array = NULL;
    size_t count = 0;
    void *tmp = NULL;
    const char default_plugin_preallocation = 16;

    if (!plugins || !plugin_count) return -1;

    plugin_array = malloc(sizeof(indigo_plugin_t *) * default_plugin_preallocation);
    if (!plugin_array) {
        return -1;
    }

    ret = get_source_dir(plugin_dir_path);
    if (!ret) {
        free(plugin_array);
        return -1;
    }

    strncat(plugin_dir_path,INDIGO_PLUGIN_DIR, sizeof(plugin_dir_path) - strlen(plugin_dir_path) - 1);

    ret = g_file_test(plugin_dir_path, G_FILE_TEST_EXISTS);
    if (ret == 0) {
        //create the plugin directory and return, since there are no plugins to load
        g_mkdir_with_parents(plugin_dir_path, 0755);
        free(plugin_array);
        *plugins = NULL;
        *plugin_count = 0;
        return 0;
    }

    plugin_dir = g_dir_open(plugin_dir_path, 0, &err);
    if (!plugin_dir) {
        free(plugin_array);
        *plugins = NULL;
        *plugin_count = 0;
        return -1;
    }

    dir_entry = g_dir_read_name(plugin_dir);
    while (dir_entry) {
        cpath = g_canonicalize_filename(dir_entry, plugin_dir_path);
        if (!cpath) {
            g_dir_close(plugin_dir);
            g_free(cpath);
            free(plugin_array);
            *plugins = NULL;
            *plugin_count = 0;
            return -1;
        }
        ret = g_file_test(cpath, G_FILE_TEST_EXISTS);
        if (ret == 0) {
            g_free(cpath);
            cpath = NULL;
            continue;
        }

        ret = g_file_test(cpath, G_FILE_TEST_IS_DIR);
        if (ret == 0) {
            // if it is a file
            //check if it is a shared object
            ret = strcmp(g_utf8_offset_to_pointer(cpath, -3),".so");
            if (ret == 0) {
                if (count >= default_plugin_preallocation) {
                    tmp = realloc(plugin_array, (count + 1) * sizeof(indigo_plugin_t *));
                    if (!tmp) {
                        *plugins = plugin_array;
                        *plugin_count = count;
                        return 1;
                    }
                    plugin_array = tmp;
                }

                ret = load_plugin(cpath, &plugin_array[count]);
                if (ret == 0) {
                    ++count;
                }
            }
        }
        g_free(cpath);
        cpath = NULL;
        dir_entry = g_dir_read_name(plugin_dir);
    }
    g_dir_close(plugin_dir);

    *plugins = plugin_array;
    *plugin_count = count;

    return 0;
}