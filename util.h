#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>

char* get_command_output(const char* path, char* arg, ...);
char* get_command_output_with_input(const char* path, const void* input, size_t input_size, char* argv[]);
int find_process(const char* user, const char* name);
int resolve_process(const char* specifier);

#endif
