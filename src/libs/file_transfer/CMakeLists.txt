add_library(file_tras SHARED
        file_transfer.c
        crypto_utils.c
        session.c
)

target_link_libraries(file_tras PUBLIC file_trans_includes)