#define _FILE_OFFSET_BITS 64

#include "symtab.h"
#include "objdump.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

// We don't want to do a million fork-execs per address processed, so we're going to cache
// what we get from objdump and make it searchable. This is mostly for fun. I want to try
// a tree.

//
//
// BEGIN AA TREE IMPLEMENTATION
//
//

typedef struct AANode
{
	struct AANode* left;
	struct AANode* right;
	int level;
	uint64_t value;
	char* strValue;
	struct AANode* treeToFree;
} AANode;

static inline AANode* skew(AANode* T)
{
	if(!T)
		return NULL;
	else if(T->left && T->left->level == T->level)
	{
		AANode* L = T->left;
		T->left = L->right;
		L->right = T;
		return L;
	}
	else
		return T;
}

static inline AANode* split(AANode* T)
{
	if(!T)
		return NULL;
	else if(T->right && T->right->right && T->level == T->right->right->level)
	{
		AANode* R = T->right;
		T->right = R->left;
		R->left = T;
		++R->level;
		return R;
	}
	else
		return T;
}

static AANode* insert(AANode* X, AANode* T)
{
	if(!T)
	{
		X->left = NULL;
		X->right = NULL;
		X->level = 1;
		return X;
	}
	{
		if(T->strValue)
		{
			int result = strcmp(X->strValue, T->strValue);
			if(result < 0)
				T->left = insert(X, T->left);
			else
				T->right = insert(X, T->right);
		}
		else
		{
			if(X->value < T->value)
				T->left = insert(X, T->left);
			else
				T->right = insert(X, T->right);

		}
	}

	T = skew(T);
	T = split(T);

	return T;
}

static AANode* searchStr(AANode* T, const char* value)
{
	while(T)
	{
		int result = strcmp(value, T->strValue);
		if(result < 0)
			T = T->left;
		else if(result > 0)
			T = T->right;
		else
			return T;
	}

	return NULL;
}

static AANode* search(AANode* T, uint64_t value)
{
	AANode* last = NULL;
	while(T)
	{
		if(value < T->value)
			T = T->left;
		else if(value > T->value)
		{
			last = T;
			T = T->right;
		}
		else
			return T;
	}
	
	return last;
}

static void free_tree(AANode* T)
{
	if(T)
	{
		free_tree(T->left);
		free_tree(T->right);
		free_tree(T->treeToFree);
		free(T);
	}
}

//
//
// END AA TREE IMPLEMENTATION
//
//

typedef struct Mapping
{
	AANode node;
	intptr_t start;
	intptr_t end;
	intptr_t image_start;
	char image_path[];
} Mapping;

typedef struct Symbol
{
	AANode node;
	intptr_t address;
	char name[];
} Symbol;

typedef struct SymbolTable
{
	AANode node;
	Symbol* table;
	char image_path[];
} SymbolTable;

struct SymtabCache
{
	Mapping* mappings;
	SymbolTable* symbols;
};

static Mapping* find_mapping_for_address(SymtabCache* cache, int process, void* address)
{
	intptr_t iAddress = (intptr_t) address;
	Mapping* mapping = (Mapping*) search((AANode*)cache->mappings, iAddress);
	if(mapping && mapping->start <= iAddress && iAddress <= mapping->end)
		return mapping;

	char image_path[PATH_MAX];
	intptr_t image_start;
	intptr_t start;
	intptr_t end;

	if(!find_image_for_address(process, address, image_path, &image_start, &start, &end))
		return NULL;

	mapping = (Mapping*) malloc(sizeof(Mapping) + strlen(image_path) + 1);
	mapping->node.value = start;
	mapping->node.strValue = NULL;
	mapping->node.treeToFree = NULL;
	mapping->start = start;
	mapping->end = end;
	mapping->image_start = image_start;
	strcpy(mapping->image_path, image_path);

	cache->mappings = (Mapping*) insert((AANode*)mapping, (AANode*)cache->mappings);

	return mapping;
}

static void cache_symbols(SymbolTable* table, const char* image)
{
	char buf[PATH_MAX];

	// dump the symbol tables for that binary we fished out of /proc/pid/maps
	char* symbolTable = get_command_output("/usr/bin/objdump", "/usr/bin/objdump", "-tT", image, NULL);
	char* symbolTableLine = strtok(symbolTable, "\n");	// TODO: Not thread-safe
	do
	{
		unsigned long long start;

		// variety of line with version information
		if(sscanf(symbolTableLine, "%llx %*s %*s %*s %*llx %*s %s", &start, buf) != 2)
		{
			// sometimes there's no version information
			if(sscanf(symbolTableLine, "%llx %*s %*s %*s %*llx %s", &start, buf) != 2)
				continue;
		}

		Symbol* symbol = (Symbol*) malloc(sizeof(Symbol) + strlen(buf) + 1);
		symbol->node.value = start;
		symbol->node.strValue = NULL;
		symbol->node.treeToFree = NULL;
		symbol->address = start;
		strcpy(symbol->name, buf);

		table->table = (Symbol*) insert((AANode*)symbol, (AANode*)table->table);
	}
	while((symbolTableLine = strtok(NULL, "\n")) != NULL);

	free(symbolTable);
}

Symbol* get_symbols(SymtabCache* cache, const char* image)
{
	SymbolTable* table = (SymbolTable*) searchStr((AANode*)cache->symbols, image);
	if(!table)
	{
		table = malloc(sizeof(SymbolTable) + strlen(image) + 1);
		table->table = NULL;
		strcpy(table->image_path, image);
		table->node.strValue = table->image_path;
		cache_symbols(table, image);
		table->node.treeToFree = (AANode*) table->table;

		cache->symbols = (SymbolTable*) insert((AANode*)table, (AANode*) cache->symbols);
	}

	return table->table;
}

const char* find_symbol_for_address(SymtabCache* cache, int process, void* address, void** symbol_address)
{
	Mapping* mapping = find_mapping_for_address(cache, process, address);
	if(!mapping)
		return NULL;

	Symbol* symbols = get_symbols(cache, mapping->image_path);
	if(!symbols)
		return NULL;

	intptr_t iAddress = ((intptr_t) address) - mapping->image_start;
	Symbol* symbol = (Symbol*) search((AANode*) symbols, iAddress);
	if(symbol)
	{
		*symbol_address = (void*) symbol->address;
		return symbol->name;
	}

	return NULL;
}

SymtabCache* new_symtab_cache()
{
	SymtabCache* ret = (SymtabCache*) malloc(sizeof(SymtabCache));
	ret->mappings = NULL;
	ret->symbols = NULL;
	return ret;
}

void free_symtab_cache(SymtabCache* cache)
{
	free_tree((AANode*)cache->mappings);
	free_tree((AANode*)cache->symbols);
	free(cache);
}
