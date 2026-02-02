# Add the library target compiled from the source files in the 'lib' subdirectory.
add_library(indigo_core SHARED indigo_core.c manager.c net_io.c packet_handler.c net_monitor.c)

# Link the library target with the interface target so that it knows where to find headers.
target_link_libraries(indigo_core PUBLIC indigo_core_includes ws2_32 IPHLPAPI event_flags queue sodium mempool file_tras hash_table)