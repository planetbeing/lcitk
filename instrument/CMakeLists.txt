add_library(heap SHARED heap.c)
set_target_properties(heap PROPERTIES PREFIX "")
set_target_properties(heap PROPERTIES COMPILE_FLAGS "-fPIC")
target_link_libraries(heap lcitk)

