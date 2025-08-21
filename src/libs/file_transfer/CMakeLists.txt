add_library(file_tras SHARED
        file_transfer.c
        crypto_utils.c
        session.c
        ../../../include/indigo_errors.h
)

target_link_libraries(file_tras PUBLIC file_trans_includes Kernel32 sodium )