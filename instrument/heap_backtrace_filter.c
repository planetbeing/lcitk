/**
 * @file heap_backtrace_filer.c
 * @author Your Mom
 *
 * Filters /tmp/malloc_log.<pid> for backtrace information and expands it symbolically, given the process id it came from
 *
 */

#define _FILE_OFFSET_BITS 64

#include "util.h"
#include "objdump.h"
#include "process.h"
#include "symtab.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char* const argv[])
{
	if(argc < 1)
	{
		printf("Usage: %s ([<user>/]exec_name | pid)\n", argv[0]);
		return 0;
	}

	int process = resolve_process(argv[1]);

	if(process == 0)
	{
		printf("Could not find process: %s\n", argv[1]);
		return 0;
	}

	SymtabCache* cache = new_symtab_cache();

	char line[4096];

	while(fgets(line, sizeof(line), stdin))
	{
		char* backtrace_start = strstr(line, "0x");
		if(!backtrace_start)
		{
			fprintf(stdout, "%s", line);
			continue;
		}

		fwrite(line, 1, backtrace_start - line, stdout);

		int first = 1;
		char* token = strtok(backtrace_start, ",");
		while(token != NULL)
		{
			if(first == 0)
			{
				fprintf(stdout, ", ");
			}

			void* address = (void*) strtoll(token, NULL, 0);
			void* symbol_address;
			const char* name = find_symbol_for_address(cache, process, address, &symbol_address);

			if(name)
				fprintf(stdout, "%s+0x%x", name, (int)((intptr_t)address - (intptr_t)symbol_address));
			else
				fprintf(stdout, "%p", address);

			first = 0;
			token = strtok(NULL, ",");
		}

		fprintf(stdout, "\n");
	}

	free_symtab_cache(cache);

	return 0;
}

