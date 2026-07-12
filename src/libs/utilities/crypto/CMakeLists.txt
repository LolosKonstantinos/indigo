add_library(crypto_utils SHARED crypto_utils.c)

target_link_libraries(crypto_utils PUBLIC crypto_includes)

target_link_libraries(crypto_utils PRIVATE PkgConfig::SODIUM PkgConfig::GLIB tp_logger config)
if(WIN32)
  target_link_libraries(crypto_utils PRIVATE Kernel32 ws2_32)
endif()
