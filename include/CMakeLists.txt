# Create an interface target to hold the include directories.
add_library(dev_disc_includes INTERFACE device_discovery.h)

add_library(file_trans_includes INTERFACE
        file_transfer.h
        session.h
        crypto_utils.h
        session_types.h
)
#utilities libraries
add_library(path_includes INTERFACE path.h)
add_library(event_flag_includes INTERFACE event_flags.h)
add_library(queue_includes INTERFACE Queue.h)
add_library(buffer_includes INTERFACE buffer.h)
add_library(mempool_includes INTERFACE mempool.h)
add_library(indigo_errors INTERFACE indigo_errors.h)


# The interface target makes all its consumers aware of the include directory.
target_include_directories(dev_disc_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(file_trans_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(path_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(event_flag_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(queue_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(buffer_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(mempool INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})


target_include_directories(indigo_errors INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})