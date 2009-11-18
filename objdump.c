#define _FILE_OFFSET_BITS 64

#include "objdump.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>

/**
 *  For the specified process pid and object image name, return the address within the process for the start of the image.
 *
 *  @param[in] process
 *  	The process's PID.
 *
 *  @param[in] image_name
 *  	The name of the image to look for. Any image with image_name as a substring is matched.
 *
 *  @param[out] image_path
 *  	The full filesystem path of the image.
 *
 *  @param[out] image_start
 *  	The starting address in virtual memory for the specified image.
 *
 *  @return
 *  	A true value if the image was found, false for failure.
 *
 */
int find_image_address(int process, const char* image_name, char image_path[PATH_MAX], intptr_t* image_start)
{
	char buf[PATH_MAX];

	*image_start = 0;

	// The first step is to find where the image is mapped.

	snprintf(buf, sizeof(buf), "/proc/%d/maps", process);

	FILE* maps = fopen(buf, "r");
	if(!maps)
		return 0;

	while(fgets(buf, sizeof(buf), maps) != NULL)
	{
		unsigned long long start;
		char permissions[PATH_MAX];
		char is_deleted[PATH_MAX];
		int scanned;

		if((scanned =
			sscanf(buf, "%llx-%*llx %s %*llx %*s %*d %s %s", &start, permissions, image_path, is_deleted)) < 3)
			continue;

		// we're looking for an entry that is both readable and executable
		if(permissions[0] != 'r' || permissions[2] != 'x')
			continue;

		// we're looking for an entry that is not deleted
		if(scanned == 4 && strncmp(is_deleted, "(deleted)", sizeof("(deleted)") - 1) == 0)
			continue;

		// the filename should also start with the image_name
		if(strstr(image_path, image_name) == NULL)
			continue;

		// this is probably it. let's use it.
		*image_start = start;
		break;
	}

	fclose(maps);

	if(*image_start == 0)
		return 0;

	// second step is to discover the offset from the start of the image the first loaded section actually is.
	char* symbolTable = get_command_output("/usr/bin/objdump", "/usr/bin/objdump", "-p", image_path, NULL);
	char* symbolTableLine = strtok(symbolTable, "\n");	// TODO: Not thread-safe
	do
	{
		unsigned long long offset;
		unsigned long long vaddr;

		if(sscanf(symbolTableLine, " LOAD off 0x%llx vaddr 0x%llx paddr 0x%*llx align %*s", &offset, &vaddr) != 2)
			continue;

		// die if this was the last line
		if((symbolTableLine = strtok(NULL, "\n")) == NULL)
			break;

		if(sscanf(symbolTableLine, " filesz 0x%*llx memsz 0x%*llx flags %s", buf) != 1)
			continue;

		// we're looking for a LOAD segment that is both readable and executable like the one in the map
		if(buf[0] != 'r' || buf[2] != 'x')
			continue;

		// we must adjust image_start by the amount the first section has shifted up from the actual start
		// of the image.
		*image_start -= vaddr - offset;		
		break;
	}
	while((symbolTableLine = strtok(NULL, "\n")) != NULL);

	free(symbolTable);

	return 1;
}

/**
 *  For the specified process pid and address, return the image that contains the address in range.
 *
 *  @param[in] process
 *  	The process's PID.
 *
 *  @param[in] address
 *  	The name of the image to look for. Any image with image_name as a substring is matched.
 *
 *  @param[out] image_path
 *  	The full filesystem path of the image.
 *
 *  @param[out] image_start
 *  	The starting address in virtual memory for the image found.
 *
 *  @param[out] range_start
 *  	The starting address in virtual memory for the mapping the address was found in.
 *
 *  @param[out] range_end
 *  	The end address in virtual memory for the mapping the address was found in.
 *
 *  @return
 *  	A true value if the image was found, false for failure.
 *
 */
int find_image_for_address(int process, void* address, char image_path[PATH_MAX], intptr_t* image_start,
		intptr_t* range_start, intptr_t* range_end)
{
	char buf[PATH_MAX];
	intptr_t iAddress = (intptr_t) address;

	*image_start = 0;

	// The first step is to find which mapping contains teh address.

	snprintf(buf, sizeof(buf), "/proc/%d/maps", process);

	FILE* maps = fopen(buf, "r");
	if(!maps)
		return 0;

	while(fgets(buf, sizeof(buf), maps) != NULL)
	{
		unsigned long long start;
		unsigned long long end;
		char is_deleted[PATH_MAX];
		int scanned;

		if((scanned =
			sscanf(buf, "%llx-%llx %*s %*llx %*s %*d %s %s", &start, &end, image_path, is_deleted)) < 3)

			continue;

		// skip if our address is not within range
		if(!(start <= iAddress && iAddress <= end))
			continue;

		// we're looking for an entry that is not deleted
		if(scanned == 4 && strncmp(is_deleted, "(deleted)", sizeof("(deleted)") - 1) == 0)
			continue;

		// this is probably it. let's use it.
		*image_start = start;
		*range_start = start;
		*range_end = end;
		break;
	}

	fclose(maps);

	if(*image_start == 0)
		return 0;

	// second step is to discover the offset from the start of the image the first loaded section actually is.
	char* symbolTable = get_command_output("/usr/bin/objdump", "/usr/bin/objdump", "-p", image_path, NULL);
	char* symbolTableLine = strtok(symbolTable, "\n");	// TODO: Not thread-safe
	do
	{
		unsigned long long offset;
		unsigned long long vaddr;

		if(sscanf(symbolTableLine, " LOAD off 0x%llx vaddr 0x%llx paddr 0x%*llx align %*s", &offset, &vaddr) != 2)
			continue;

		// die if this was the last line
		if((symbolTableLine = strtok(NULL, "\n")) == NULL)
			break;

		if(sscanf(symbolTableLine, " filesz 0x%*llx memsz 0x%*llx flags %s", buf) != 1)
			continue;

		// we're looking for a LOAD segment that is both readable and executable like the one in the map
		// we probably don't need to worry about permissions here.
		if(buf[0] != 'r' || buf[2] != 'x')
			continue;

		// we must adjust image_start by the amount the first section has shifted up from the actual start
		// of the image.
		*image_start -= vaddr - offset;		
		break;
	}
	while((symbolTableLine = strtok(NULL, "\n")) != NULL);

	free(symbolTable);

	return 1;
}

/**
 *  For the specified process pid and object image name, return the address within the process for the relocation of the named function.
 *
 *  @param[in] process
 *  	The process's PID.
 *
 *  @param[in] image_name
 *  	The name of the image to look for. Any image with image_name as a substring is matched.
 *
 *  @param[in] func
 *  	The name of the function to find.
 *
 *  @return
 *  	The address of the relocation within the process.
 *
 */
void* find_relocation(int process, const char* image_name, const char* func)
{
	char buf[PATH_MAX];
	char image[PATH_MAX];
	intptr_t image_start = 0;
	intptr_t func_start = 0;

	if(!find_image_address(process, image_name, image, &image_start))
		return NULL;

	// dump the relocation tables for that binary we fished out of /proc/pid/maps
	char* symbolTable = get_command_output("/usr/bin/objdump", "/usr/bin/objdump", "-rR", image, NULL);
	char* symbolTableLine = strtok(symbolTable, "\n");	// TODO: Not thread-safe
	do
	{
		unsigned long long start;

		if(sscanf(symbolTableLine, "%llx %*s %s", &start, buf) != 2)
			continue;

		// we're only interested if we have an exact match for the symbol name
		if(strcmp(buf, func) != 0)
			continue;

		func_start = start;
	}
	while((symbolTableLine = strtok(NULL, "\n")) != NULL);

	free(symbolTable);

	if(func_start == 0)
		return NULL;

	return (void*)(image_start + func_start);
}

/**
 *  For the specified process pid, and object image name, return the address within the process for the named function.
 *
 *  @param[in] process
 *  	The process's PID.
 *
 *  @param[in] image_name
 *  	The name of the image to look for. Any image with image_name as a substring is matched.
 *
 *  @param[in] func
 *  	The name of the function to find.
 *
 *  @param[out] image_path
 *  	Full path of the image with the function. This must be freed by the caller.
 *  	Changed only if find_function succeeds.
 *
 *  @return
 *  	The address of the function within the process. NULL if nothing was found.
 *
 */
void* find_function(int process, const char* image_name, const char* func, char** image_path)
{
	char buf[PATH_MAX];
	char image[PATH_MAX];
	intptr_t image_start = 0;
	intptr_t func_start = 0;

	if(!find_image_address(process, image_name, image, &image_start))
		return NULL;

	// second step is to find out where the function is in the libc symbol table
	// I think on the balance, it's better to use the binutils shell commands than try
	// to do something fancy. This way we get a free disassembler and everything.

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

		// we're only interested if we have an exact match for the symbol name
		if(strcmp(buf, func) != 0)
			continue;

		func_start = start;
	}
	while((symbolTableLine = strtok(NULL, "\n")) != NULL);

	free(symbolTable);

	if(func_start == 0)
		return NULL;

	if(image_path != NULL)
		*image_path = strdup(image);

	return (void*)(image_start + func_start);
}

/**
 *  For the specified process pid, return the address within the process for the named libc function.
 *
 *  @param[in] process
 *  	The process's PID.
 *
 *  @param[in] func
 *  	The name of the function to find.
 *
 *  @return
 *  	The address of the function within the process. NULL if nothing was found.
 *
 */
void* find_libc_function(int process, const char* func)
{
	return find_function(process, "/libc", func, NULL);
}
