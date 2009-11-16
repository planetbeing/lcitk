/**
 * @file console.c
 * @author Your Mom
 *
 * A framework for injecting arbitrary code to interpose code within running Linux processes.
 * This program uses LCITK to run a shell that can run arbitrary functions within a target
 * process. Kind of like gdb, only this program is not permanently attached.
 *
 */

#include "util.h"
#include "objdump.h"
#include "process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/mman.h>

// Return chopped up pieces like strtok, but using an outside state variable, ignoring excess whitespace
// and paying attention to quotes.
char* tokenizer(char** state)
{
	char* str = *state;
	char* start = str;
	int inquotes = 0;
	int blank = 1;

	if(*str == '\0')
		return NULL;

	while(((*str != ' ' && *str != '\n' && *str != '\t') || inquotes || blank) && *str != '\0')
	{
		if(*str == '\"')
			inquotes = !inquotes;
		
		if(*str != ' ' && *str != '\t' && *str != '\t')
			blank = 0;

		if(blank)
			start++;

		*str++;
	}
	
	if(*str != '\0')
	{
		*str = '\0';
		*state = str + 1;
	}
	else
	{
		*state = str;
	}

	return start;
}

int main(int argc, const char* const argv[])
{
	if(argc < 2)
	{
		printf("Usage: %s ([<user>/]exec_name | pid)\n", argv[0]);
		return 0;
	}

	using_history();

	read_history(".console_history");

	int process = resolve_process(argv[1]);

	if(process == 0)
	{
		printf("Could not find process: %s\n", argv[1]);
		return 0;
	}

	printf("Target process: %d\n", process);
	printf("Type '#quit' to exit this program, #process <process specifier> to change processes.\n\n");

	void* target_mmap = find_libc_function(process, "mmap");
	void* target_munmap = find_libc_function(process, "munmap");

	int done = 0;
	while(!done)
	{
		char* line = readline("> ");

		if(line && *line)
		{
			char* expanded;
			int result = history_expand(line, &expanded);
			if(result < 0 || result == 2)
			{
				if(result == 2)
				{
					printf("%s\n", expanded);
				}

				free(line);
				free(expanded);
				continue;
			}

			free(line);
			add_history(expanded);

			if(strcmp(expanded, "#quit") == 0)
				done = 1;
			else if(strncmp(expanded, "#process ", sizeof("#process ") - 1) == 0)
			{
				int p = resolve_process(expanded + sizeof("#process ") - 1);
				if(p != 0)
				{
					process = p;
					printf("New target process: %d\n", p);
				}
				else
				{
					printf("Could not find process: %s\n", expanded + sizeof("#process ") - 1);
				}
			}
			else
			{
				intptr_t* strings = NULL;
				size_t* stringlens = NULL;
				int numstrings = 0;

				char* func_name = NULL;
				uint64_t* args = NULL;
				int numargs = 0;
				char* tokenizer_state = expanded;
				char* token = tokenizer(&tokenizer_state);
				do
				{
					if(!func_name)
					{
						func_name = strdup(token);
					}
					else
					{
						args = (uint64_t*) realloc(args, sizeof(uint64_t) * (numargs + 1));	

						if(token[0] == '\"')
						{
							int tokenLength = strlen(token);
							if(token[tokenLength-1] == '\"')
							{
								// Make tokenLength = string length + 1 (for the \0)
								// Make token the start of the string
								token[tokenLength-1] = '\0';
								++token;
								--tokenLength;

								printf("Allocating string \"%s\" ... ", token);

								// Allocate it within target process and copy the string
								strings = (intptr_t*) realloc(strings,
										sizeof(intptr_t) * (numstrings + 1));	

								stringlens = (intptr_t*) realloc(stringlens,
										sizeof(intptr_t) * (numstrings + 1));	

								strings[numstrings] =
									call_function_in_target64(process,
										target_mmap,
										6,
										0, tokenLength, PROT_READ | PROT_WRITE,
										MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

								stringlens[numstrings] = tokenLength;

								process_write(process, token, tokenLength,
										strings[numstrings]);
							
								process_read(process, token, tokenLength,
										strings[numstrings]);

								args[numargs] = strings[numstrings];

								printf("(%s) 0x%llx\n", token, strings[numstrings]);
								++numstrings;
							}
						}
						else
						{
							args[numargs] = strtoll(token, NULL, 0);
						}

						++numargs;
					}
				}
				while((token = tokenizer(&tokenizer_state)) != NULL);

				char* image_path = NULL;
				void* function = find_function(process, "", func_name, &image_path);
				if(!function)
					function = find_function(process, "/libc", func_name, &image_path);

				int i;

				if(function)
				{
					printf("Calling '%s' at 0x%p (%s) with %d arguments (",
							func_name, function, image_path, numargs);

					for(i = 0; i < numargs; i++)
					{
						if(i != 0)
							printf(", ");

						printf("%llx", args[i]);
					}

					printf(")...\n");

					uint64_t ret = call_function_in_target_with_args64(process, function, numargs, args);
					free(image_path);
				
					printf("Return value (hex/dec/oct): 0x%llx / %lld / 0%llo\n", ret, ret, ret);
				}
				else
				{
					printf("Cannot find function '%s' to call.\n", func_name);
				}

				free(func_name);

				if(args)
					free(args);

				for(i = 0; i < numstrings; i++)
				{
					printf("Freeing string at 0x%llx.\n", strings[i]);
					call_function_in_target64(process, target_munmap, 2, strings[i], stringlens[i]);
				}

				if(strings)
					free(strings);

				if(stringlens)
					free(stringlens);
			}

			free(expanded);
		}
	}

	write_history(".console_history");
}

