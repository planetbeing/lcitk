/**
 * @file console.c
 * @author Your Mom
 *
 * A framework for injecting arbitrary code to interpose code within running Linux processes.
 * This program uses LCITK to run a shell that can run arbitrary functions within a target
 * process. Kind of like gdb, only this program is not permanently attached.
 *
 */

#define _FILE_OFFSET_BITS 64

#include "util.h"
#include "objdump.h"
#include "process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/mman.h>

jmp_buf abort_readline;

int done = 0;

// forward declarations
char* tokenizer(char** state);
char* handle_escape(char* str);
void process_command(int process, void* target_mmap, void* target_munmap, char* expanded);

void interrupt_handler(int signum)
{
	done = 1;
	printf("\n");	// blank line to get off the input line
	longjmp(abort_readline, 1);
}

int main(int argc, const char* const argv[])
{
	if(argc < 2)
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

	printf("Target process: %d\n", process);
	printf("Type '#quit' to exit this program, #process <process specifier> to change processes.\n\n");

	void* target_mmap = find_libc_function(process, "mmap");
	void* target_munmap = find_libc_function(process, "munmap");

	// detach and save history gracefully upon receipt of these signals
	
	signal(SIGINT, interrupt_handler);
	signal(SIGTERM, interrupt_handler);
	signal(SIGALRM, interrupt_handler);
	signal(SIGHUP, interrupt_handler);

	rl_set_signals();

	using_history();

	read_history(".console_history");

	done = 0;
	while(!done)
	{
		if(setjmp(abort_readline) != 0)
			continue;

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
				process_command(process, target_mmap, target_munmap, expanded);
			}

			free(expanded);
		}
	}

	write_history(".console_history");
}

// Perform argument parsing and possibly execute a command in the inferior
void process_command(int process, void* target_mmap, void* target_munmap, char* expanded)
{
	intptr_t* strings = NULL;
	size_t* stringlens = NULL;
	int numstrings = 0;

	char* func_name = NULL;
	uint64_t* args = NULL;
	int numargs = 0;
	int bad_args = 0;
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
				char* endptr;
				args[numargs] = strtoll(token, &endptr, 0);
				if(*endptr != '\0') // check if valid number found
				{
					// symbol name
					void* sym = find_function(process, "", token, NULL);
					if(!sym)
						sym = find_function(process, "/libc", token, NULL);

					if(sym)
					{
						printf("Found symbol %s at %p\n", token, sym);
						args[numargs] = (intptr_t) sym;
					}
					else
					{
						printf("Could not find symbol %s\n", token);
						bad_args = 1;
					}
				}
			}

			++numargs;
		}
	}
	while((token = tokenizer(&tokenizer_state)) != NULL);

	int i;

	if(func_name[0] != '#' && !bad_args)
	{
		char* image_path = NULL;
		void* function = find_function(process, "", func_name, &image_path);
		if(!function)
			function = find_function(process, "/libc", func_name, &image_path);

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
	}
	else
	{
		if(!bad_args)
		{
			if(strcmp(func_name, "#read") == 0)
			{
				if(numargs != 2)
				{
					printf("#read <addr> <len>\n");
				}
				else
				{
					char* buffer = (char*) malloc(args[1]);
					memset(buffer, 0, args[1]);
					process_read(process, buffer, args[1], args[0]);
					char* output = get_command_output_with_input(
							"/usr/bin/hexdump", buffer, args[1],
							(char*[]){"/usr/bin/hexdump", "-C", NULL});

					printf("%s\n", output);
					free(output);
				}
			}
		}
	}

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

// Return chopped up pieces like strtok, but using an outside state variable, ignoring excess whitespace
// and paying attention to quotes, also performing C style escape expansion.
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
		if(*str == '\\')
		{
			str = handle_escape(str);
			continue;
		}

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

// Perform C-style escape expansion on the following escape sequence + str, moving the str forward
// to cover the memory once occupied by the escape sequence
char* handle_escape(char* str)
{
	int escapelen;	// number of characters in the escape sequence, e.g. '\n' is 2
	int codelen;	// number of characters coded for, e.g. '\n' is 1

	switch(*(str + 1))
	{
		case 'a':
			escapelen = 2;
			codelen = 1;
			*str = '\a';
			break;

		case 'b':
			escapelen = 2;
			codelen = 1;
			*str = '\b';
			break;

		case 'f':
			escapelen = 2;
			codelen = 1;
			*str = '\f';
			break;

		case 'n':
			escapelen = 2;
			codelen = 1;
			*str = '\n';
			break;

		case 'r':
			escapelen = 2;
			codelen = 1;
			*str = '\r';
			break;

		case 't':
			escapelen = 2;
			codelen = 1;
			*str = '\t';
			break;

		case 'x':
			{
				if(*(str + 2) == '\0' || *(str + 3) == '\0')
				{
					escapelen = 1;
					codelen = 1;
					break;
				}

				char buf[3];
				char* endptr;
				buf[0] = *(str + 2);
				buf[1] = *(str + 3);
				buf[2] = '\0';
				*str = (char)strtol(buf, &endptr, 16);
				if(*endptr != '\0')
				{
					*str = '\\';
					escapelen = 1;
					codelen = 1;
					break;
				}

				escapelen = 4;
				codelen = 1;
				break;
			}

		case '\0':
			escapelen = 1;
			codelen = 1;
			break;

		default:
			if('0' <= *(str + 1) && *(str + 1) <= '9')
			{
				// octal
				if(*(str + 1) == '\0' || *(str + 2) == '\0' || *(str + 3) == '\0')
				{
					escapelen = 1;
					codelen = 1;
					break;
				}

				char buf[4];
				char* endptr;
				buf[0] = *(str + 1);
				buf[1] = *(str + 2);
				buf[2] = *(str + 3);
				buf[3] = '\0';
				*str = (char)strtol(buf, &endptr, 8);
				if(*endptr != '\0')
				{
					*str = '\\';
					escapelen = 1;
					codelen = 1;
					break;
				}

				escapelen = 4;
				codelen = 1;
				break;
			}

			*str = *(str + 1);
			escapelen = 2;
			codelen = 1;
			break;
	}

	// shift the entire buffer forward by the appropriate number of characters
	memmove(str + codelen, str + escapelen, strlen(str + escapelen) + 1);
	str += codelen;

	return str;
}

