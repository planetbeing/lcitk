#define _FILE_OFFSET_BITS 64

#include "symtab.h"
#include "objdump.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

// We don't want to do a million fork-execs per address processed, so we're going to cache
// what we get from objdump and make it searchable. This is mostly for fun. I want to try
// a tree.

//
//
// BEGIN AA TREE IMPLEMENTATION
//
//

/**
 * An internal data structure representing a node in an AA tree.
 *
 */
typedef struct AANode
{
	struct AANode* left;
	struct AANode* right;
	int level;
	uint64_t value;			/// Integer value to determine node order, greater numbers on the right (only used if strValue is NULL)
	char* strValue;			/// String value to determine order, alphabetically greater strings on the right
	struct AANode** treeToFree;	/// If not null, free this AA Tree as well when this node is being freed
} AANode;

/**
 *  Rebalance an AA tree with a skew operation.
 *
 *  @param[in] T
 *  	Node representing an AA tree to be rebalanced
 *
 *  @return
 *  	Node representing a rebalanced AA tree.
 *
 */
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

/**
 *  Rebalance an AA tree with a split operation.
 *
 *  @param[in] T
 *  	Node representing an AA tree to be rebalanced
 *
 *  @return
 *  	Node representing a rebalanced AA tree.
 *
 */
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

/**
 *  Insert a node into an AA tree.
 *
 *  @param[in] X
 *  	Node representing the node to be inserted.
 *
 *  @param[in] T
 *  	The root of the AA tree to insert the node into
 *
 *  @return
 *  	A balanced version of T which includes X.
 *
 */
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

/**
 *  Search an AA tree by its strValue
 *
 *  @param[in] T
 *  	The root of the AA tree to be searched.
 *
 *  @param[in] value
 *  	The string to be searched for in the AA tree.
 *
 *  @return
 *  	A node of T which has value as its strValue. If no such node exists, NULL is returned.
 *
 */
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

/**
 *  Search an AA tree by its integer value, returning the largest node that is less than or equal to value.
 *
 *  @param[in] T
 *  	The root of the AA tree to be searched.
 *
 *  @param[in] value
 *  	The integer value to be searched for.
 *
 *  @return
 *  	The largest node of T which has a value less than or equal to value. If no such node exists, NULL is returned.
 *
 */
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

/**
 *  Free the memory associated with an AA tree.
 *
 *  @param[in] T
 *  	The root of the AA tree to be freed.
 *
 */
static void free_tree(AANode* T)
{
	if(T)
	{
		free_tree(T->left);
		free_tree(T->right);

		if(T->treeToFree)
			free_tree(*T->treeToFree);

		free(T);
	}
}

//
//
// END AA TREE IMPLEMENTATION
//
//

/**
 * Represents a region of memory mapped inside a particular process.
 *
 */
typedef struct Mapping
{
	AANode node;
	intptr_t start;			/// Start of the memory region
	intptr_t end;			/// End of the memory region
	intptr_t image_start;		/// Address in memory other addresses in the associated binary object are based off
	char image_path[];		/// Full path of the binary object associated with this memory region.
} Mapping;

/**
 * Represents a symbol inside a binary object.
 *
 */
typedef struct Symbol
{
	AANode node;
	intptr_t address;		/// Offset from the base address of the binary object the symbol is located at.
	char name[];			/// Name of the symbol
} Symbol;

/**
 * Represents the entire symbol table of a binary object
 *
 */
typedef struct SymbolTable
{
	AANode node;
	Symbol* table;			/// The AA tree of symbols inside the symbol table.
	char image_path[];		/// The full path of the binary object.
} SymbolTable;

/**
 * Table of memory mappings of a particular process id.
 *
 */
typedef struct MappingTable
{
	AANode node;
	int process;			/// The process the table is for.
	Mapping* table;			/// The AA tree of mappings for the process.
} MappingTable;

/**
 *  Symbol table caches optimize translating addresses to symbols which otherwise would cost
 *  several objdump calls and unnecessarily duplicated work sorting and searching those
 *  results.
 */
struct SymtabCache
{
	MappingTable* mappings;
	SymbolTable* symbols;
};

/**
 *  Finds a Mapping for an address in some process's memory
 *
 *  @param[in] cache
 *  	The symbol table cache handle.
 *
 *  @param[in] process
 *  	PID of the process to search.
 *
 *  @return
 *  	A Mapping struct with information on the region of memory the specified address i in
 *
 */
static Mapping* find_mapping_for_address(SymtabCache* cache, int process, void* address)
{
	// match process to mappings
	MappingTable* table = (MappingTable*) search((AANode*)cache->mappings, process);
	if(!table)
	{
		table = malloc(sizeof(MappingTable));
		table->table = NULL;
		table->node.value = process;
		table->node.strValue = NULL;
		table->node.treeToFree = (AANode**) &table->table;

		cache->mappings = (MappingTable*) insert((AANode*)table, (AANode*) cache->mappings);
	}

	// match address to mapping
	intptr_t iAddress = (intptr_t) address;
	Mapping* mapping = (Mapping*) search((AANode*)table->table, iAddress);
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

	table->table = (Mapping*) insert((AANode*)mapping, (AANode*)table->table);

	return mapping;
}

/**
 *  Reads symbols for a particular image file and stores them  in an AA tree.
 *
 *  @param[in] table
 *  	The symbol table to store the AA tree in.
 *
 *  @param[in] image
 *  	The full path of the binary object whose symbols are to be cached.
 *
 */
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

/**
 *  Returns a AA tree with symbols for a specified binary object.
 *
 *  @param[in] cache
 *  	The symbol table cache.
 *
 *  @param[in] image
 *  	The full path of the binary object whose symbols are to be returned.
 *
 *  @return
 *  	An AA tree with the symbols of image.
 *
 */
Symbol* get_symbols(SymtabCache* cache, const char* image)
{
	SymbolTable* table = (SymbolTable*) searchStr((AANode*)cache->symbols, image);
	if(!table)
	{
		table = malloc(sizeof(SymbolTable) + strlen(image) + 1);
		table->table = NULL;
		strcpy(table->image_path, image);
		table->node.strValue = table->image_path;
		table->node.treeToFree = (AANode**) &table->table;
		cache_symbols(table, image);

		cache->symbols = (SymbolTable*) insert((AANode*)table, (AANode*) cache->symbols);
	}

	return table->table;
}

/**
 *  Finds the name of a symbol for an address in a process.
 *
 *  The symbol returned will be a symbol in the binary object the addressed is mapped for having an address just below the address specified.
 *
 *  @param[in] cache
 *  	The symbol table cache handle.
 *
 *  @param[in] process
 *  	PID of the process to search.
 *
 *  @param[in] address
 *  	The address to look up.
 *
 *  @param[out] symbol_address
 *  	If the symbol was found, this will be the exact address of the symbol.
 *
 *  @return
 *  	The name of the symbol.
 *
 */
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

/**
 *  Initialize a new symbol table cache. Symbol table caches optimize translating addresses to symbols which
 *  otherwise would cost several objdump calls and unnecessarily duplicated work sorting and searching those
 *  results.
 *
 *  @return
 *  	A handle to a symbol table cache that can be used with find_symbol_for_address
 *
 */
SymtabCache* new_symtab_cache()
{
	SymtabCache* ret = (SymtabCache*) malloc(sizeof(SymtabCache));
	ret->mappings = NULL;
	ret->symbols = NULL;
	return ret;
}

/**
 *  Frees an existing symbol table cache.
 *
 *  @param[in] cache
 *  	The cache to be freed.
 *
 */
void free_symtab_cache(SymtabCache* cache)
{
	free_tree((AANode*)cache->mappings);
	free_tree((AANode*)cache->symbols);
	free(cache);
}
