cmake_minimum_required(VERSION 2.6)
project(LCITK)

include_directories(${LCITK_SOURCE_DIR})

add_library(lcitk util.c objdump.c process.c asm.c)
set_target_properties(lcitk PROPERTIES COMPILE_FLAGS "-fPIC")

add_executable(inject inject.c)
target_link_libraries(inject lcitk)

SET(Readline_DIR ${LCITK_SOURCE_DIR})
find_package(Readline)

if(READLINE_FOUND)
	include_directories(${READLINE_INCLUDE_DIR})
	add_executable(console console.c)
	target_link_libraries(console lcitk ${READLINE_LIBRARIES})
endif(READLINE_FOUND)

add_subdirectory(instrument)

