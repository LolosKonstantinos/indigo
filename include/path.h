//
// Created by Constantin on 18/08/2025.
//

#ifndef PATH_H
#define PATH_H

typedef struct path {
    wchar_t *pathname;
    size_t pathname_len;
    uint64_t flags;
}path;

void path_join(path *path_1, path *path_);
#endif //PATH_H
