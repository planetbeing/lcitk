#ifndef OBJDUMP_H
#define OBJDUMP_H

#include <stdint.h>
#include <limits.h>

int find_image_address(int process, const char* image_name, char image_path[PATH_MAX], intptr_t* image_start);
int find_image_for_address(int process, void* address, char image_path[PATH_MAX], intptr_t* image_start,
		intptr_t* range_start, intptr_t* range_end);
void* find_relocation(int process, const char* image_name, const char* func);
void* find_function(int process, const char* image_name, const char* func, char** image_path);
void* find_libc_function(int process, const char* func);

#endif
