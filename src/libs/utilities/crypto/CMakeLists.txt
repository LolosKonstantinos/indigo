add_library(crypto_utils SHARED crypto_utils.c)

target_link_libraries(crypto_utils PUBLIC crypto_includes)

target_include_directories(crypto_utils PRIVATE ${SODIUM_STATIC_LIBRARY_DIRS})
target_link_libraries(crypto_utils PRIVATE ${SODIUM_STATIC_LIBRARIES} PkgConfig::GLIB tp_logger config)
if(WIN32)
  target_link_libraries(crypto_utils PRIVATE Kernel32 ws2_32)
endif()
