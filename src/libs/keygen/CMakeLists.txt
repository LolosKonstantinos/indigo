add_library(keygen SHARED
    keygen.c)

target_link_libraries(keygen PUBLIC keygen_includes libcrypto sodium)