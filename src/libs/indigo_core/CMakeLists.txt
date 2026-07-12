add_library(indigo_core SHARED  manager.c
                                net_io.c
                                packet_handler.c
                                net_monitor.c)

target_link_libraries(indigo_core PUBLIC indigo_core_includes)
target_link_libraries(indigo_core PRIVATE
        event_flags
        queue
        sodium
        mempool
        crypto_utils
        lht
        binary_tree
        config
        PkgConfig::GLIB
        logger)
if(WIN32)
  target_link_libraries(indigo_core PRIVATE ws2_32 IPHLPAPI)
elseif(LINUX)

elseif(APPLE)

endif()
