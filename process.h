#ifndef PROCESS_H
#define PROCESS_H

#include <stdlib.h>
#include <stdint.h>

void process_read(int process, void* buf, size_t count, off_t addr);
void process_write(int process, const void* buf, size_t count, off_t addr);
uint64_t call_function_in_target64(int process, void* function, int numargs, ...);
uint64_t call_function_in_target_with_args64(int process, void* function, int numargs, uint64_t* args);
void* inject_so(int process, const char* filename);
int uninject_so(int process, void* handle);

#endif
