# Add the library target compiled from the source files in the 'lib' subdirectory.
add_library(dev_disc SHARED device_discovery.c
        ../../../include/indigo_errors.h)

# Link the library target with the interface target so that it knows where to find headers.
target_link_libraries(dev_disc PUBLIC dev_disc_includes ws2_32 IPHLPAPI event_flags queue)