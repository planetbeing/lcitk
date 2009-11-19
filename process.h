#ifndef PROCESS_H
#define PROCESS_H

#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdint.h>

void process_read(int process, void* buf, size_t count, uintptr_t addr);
void process_write(int process, const void* buf, size_t count, uintptr_t addr);
uintptr_t call_function_in_target(int process, void* function, int numargs, ...);
uintptr_t call_function_in_target_with_args(int process, void* function, int numargs, uintptr_t* args);
void* inject_so(int process, const char* filename);
int uninject_so(int process, void* handle);

#endif
