#define _FILE_OFFSET_BITS 64

#include "objdump.h"
#include "util.h"
#include "process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <elf.h>


/**
 *  For the specified process pid and ELF header address inside the process, load information from the header.
 *
 *  @param[in] process
 *  	The process's PID.
 *
 *  @param[in] elf_start
 *  	The virtual address of the ELF header of the image within the process we are interested in.
 *
 *  @param[out] image_start
 *  	If not NULL, image_start will contain the starting address in virtual memory for the specified image.
 *
 *  @param[out] entry
 *  	If not NULL, entry will contain the virtual address of the entry point for the specified image.
 *
 *  @return
 *  	0 on failure, 1 on success.
 *
 */
int find_image_load_information(int process, uintptr_t elf_start, uintptr_t* image_start, uintptr_t* entry)
{
#if __WORDSIZE == 64
	Elf64_Ehdr elf;
#else
	Elf32_Ehdr elf;
#endif

	// read the main elf header
	process_read(process, &elf, sizeof(elf), elf_start);

	// fail if the ELF file doesn't match our architecture
#if __WORDSIZE == 64
	if(elf.e_ident[EI_CLASS] != ELFCLASS64)
		return 0;
#else
	if(elf.e_ident[EI_CLASS] != ELFCLASS32)
		return 0;
#endif

	// read end all the program headers
	char* phdr_buffer;
	int phdrs_size;
	phdrs_size = elf.e_phentsize * elf.e_phnum;
	phdr_buffer = (char*) malloc(phdrs_size);
	process_read(process, phdr_buffer, phdrs_size, elf_start + elf.e_phoff);

	// find the program header that is a PT_LOAD that is responsible for loading
	// the ELF header (which is at offset 0x0), but loop through them all if necessary
	int i;
	for(i = 0; i < elf.e_phnum; i++)
	{
#if __WORDSIZE == 64
		Elf64_Phdr* phdr = (Elf64_Phdr*)(phdr_buffer + (i * elf.e_phentsize));
#else
		Elf32_Phdr* phdr = (Elf32_Phdr*)(phdr_buffer + (i * elf.e_phentsize));
#endif

		// find the program header responsible for loading the ELF header
		if(phdr->p_type == PT_LOAD || phdr->p_offset == 0)
		{
			uintptr_t img_start = elf_start - phdr->p_vaddr;
			if(image_start)
				*image_start = img_start;

			if(entry)
				*entry = elf.e_entry + img_start;

			free(phdr_buffer);
			return 1;
		}
	}

	free(phdr_buffer);
	return 0;
}

/**
 *  For the specified process pid, find the address in its memory of its entry point.
 *
 *  @param[in] process
 *  	The process's PID.
 *
 *  @return
 *  	The address of the process's entry point as defined by its main executable. 0 if there was an error.
 *
 */
uintptr_t find_process_entry_point(int process)
{
	char buf[PATH_MAX];
	char main_exe_path[PATH_MAX];

	// grab the main exe's path to match to some entry in maps.
	snprintf(buf, sizeof(buf), "/proc/%d/exe", process);
	int main_exe_path_len = readlink(buf, main_exe_path, sizeof(main_exe_path));
	if(main_exe_path_len == -1)
		return 0;

	main_exe_path[main_exe_path_len] = '\0';
	
	// open maps and try to find the main exe
	snprintf(buf, sizeof(buf), "/proc/%d/maps", process);

	FILE* maps = fopen(buf, "r");
	if(!maps)
		return 0;

	intptr_t elf_start = -1;
	while(fgets(buf, sizeof(buf), maps) != NULL)
	{
		unsigned long long start;
		char image_path[PATH_MAX];
		int scanned;

		if((scanned = sscanf(buf, "%llx-%*x %*s %*x %*s %*d %s", &start, image_path)) != 2)
			continue;

		if(strcmp(image_path, main_exe_path) != 0)
			continue;

		elf_start = start;
		break;
	}

	fclose(maps);

	// main exe entry not found. Bizarre.
	if(elf_start == -1)
		return 0;

	// find the entry point based on the main exe ELF header
	uintptr_t ret;
	if(!find_image_load_information(process, elf_start, NULL, &ret))
		return 0;

	return ret;
}

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
int find_image_address(int process, const char* image_name, char image_path[PATH_MAX], uintptr_t* image_start)
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
		int scanned;

		if((scanned = sscanf(buf, "%llx-%*x %s %*x %*s %*d %s", &start, permissions, image_path)) != 3)
			continue;

		// we're looking for an entry that is both readable and executable
		if(permissions[0] != 'r' || permissions[2] != 'x')
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
	if(!find_image_load_information(process, *image_start, image_start, NULL))
		return 0;

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
int find_image_for_address(int process, void* address, char image_path[PATH_MAX], uintptr_t* image_start,
		uintptr_t* range_start, uintptr_t* range_end)
{
	char buf[PATH_MAX];
	uintptr_t iAddress = (uintptr_t) address;

	*image_start = 0;

	// The first step is to find which mapping contains the address.

	snprintf(buf, sizeof(buf), "/proc/%d/maps", process);

	FILE* maps = fopen(buf, "r");
	if(!maps)
		return 0;

	while(fgets(buf, sizeof(buf), maps) != NULL)
	{
		unsigned long long start;
		unsigned long long end;
		int scanned;

		if((scanned = sscanf(buf, "%llx-%llx %*s %*x %*s %*d %s", &start, &end, image_path)) != 3)
			continue;

		// skip if our address is not within range
		if(!(start <= iAddress && iAddress <= end))
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

		if(sscanf(symbolTableLine, " LOAD off 0x%llx vaddr 0x%llx paddr 0x%*x align %*s", &offset, &vaddr) != 2)
			continue;

		// die if this was the last line
		if((symbolTableLine = strtok(NULL, "\n")) == NULL)
			break;

		if(sscanf(symbolTableLine, " filesz 0x%*x memsz 0x%*x flags %s", buf) != 1)
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
	uintptr_t image_start = 0;
	uintptr_t func_start = 0;

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
	uintptr_t image_start = 0;
	uintptr_t func_start = 0;

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
		if(sscanf(symbolTableLine, "%llx %*s %*s %*s %*x %*s %s", &start, buf) != 2)
		{
			// sometimes there's no version information
			if(sscanf(symbolTableLine, "%llx %*s %*s %*s %*x %s", &start, buf) != 2)
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
