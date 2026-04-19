add_library(crypto_utils SHARED crypto_utils.c)

target_link_libraries(crypto_utils PUBLIC crypto_includes)
target_link_libraries(crypto_utils PRIVATE Kernel32 sodium ws2_32)