add_library(indigo_core SHARED  manager.c
                                net_io.c
                                packet_handler.c
                                net_monitor.c)

target_link_libraries(indigo_core PUBLIC indigo_core_includes)
target_link_libraries(indigo_core PRIVATE
        indigo_core_includes
        ws2_32
        IPHLPAPI
        event_flags
        queue
        sodium
        mempool
        crypto_utils
        lht
        binary_tree
        config
        PkgConfig::GLIB)
