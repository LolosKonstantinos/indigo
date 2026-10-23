add_library(indigo_api STATIC indigo_api.c)

target_link_libraries(indigo_api PUBLIC indigo_api_includes
        indigo_plugin
                                    queue
                                    event_flags)

