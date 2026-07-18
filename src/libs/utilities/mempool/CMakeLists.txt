add_library(mempool SHARED mempool.c)

target_link_libraries(mempool PUBLIC mempool_includes tp_logger)

find_library(MATH_LIB m)

if(MATH_LIB)
  target_link_libraries(mempool PRIVATE ${MATH_LIB})
endif()
