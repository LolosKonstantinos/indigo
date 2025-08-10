# Create an interface target to hold the include directories.
add_library(dev_disc_includes INTERFACE
        Queue.h
        device_discovery.h
        event_flags.h)

add_library(file_trans_includes INTERFACE
        file_transfer.h
        session.h
        crypto_utils.h
)
# The interface target makes all its consumers aware of the include directory.
target_include_directories(dev_disc_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(file_trans_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})