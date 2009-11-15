#ifndef UTIL_H
#define UTIL_H

char* get_command_output(const char* path, char* arg, ...);
int find_process(const char* user, const char* name);
int resolve_process(const char* specifier);

#endif
