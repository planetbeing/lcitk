#ifndef SYMTAB_H
#define SYMTAB_H

#include <stdint.h>

struct SymtabCache;
typedef struct SymtabCache SymtabCache;

SymtabCache* new_symtab_cache();
void free_symtab_cache(SymtabCache* cache);
const char* find_symbol_for_address(SymtabCache* cache, int process, void* address, void** symbol_address);
#endif
