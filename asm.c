#include "util.h"
#include "process.h"
#include "objdump.h"
#include "asm.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>

/**
 *  Populates an Instruction struct based on one line of objdump -D output
 *
 *  @param[in] line
 *  	A line from objdump -D output containing the disassembly to parse.
 *
 *  @param[out] insn
 *  	The parsed instruction.
 *
 */
int parse_objdump_asm(const char* line, Instruction* inst)
{
	char buf[PATH_MAX];
	int i;

	// initial whitespace
	while((*line == ' ' || *line == '\t') && *line != '\0')
		++line;

	// check for error
	if(*line == '\0')
		return 0;

	// address
	i = 0;
	while(*line != ':' && *line != '\0')
	{
		buf[i++] = *line++;
	}
	buf[i] = '\0';
	sscanf(buf, "%llx", &inst->address);

	if(!('0' <= buf[0] && buf[0] <= '9'))
	{
		return 0;
	}

	// skip colon
	++line;

	// more whitespace
	while((*line == ' ' || *line == '\t') && *line != '\0')
		++line;

	// check for error
	if(*line == '\0')
		return 0;

	// opcodes
	i = 0;
	buf[2] = '\0';
	while(*line != ' ' && line[0] != '\0' && line[1] != '\0')
	{
		unsigned int opcode;
		buf[0] = line[0];
		buf[1] = line[1];
		sscanf(buf, "%x", &opcode);
		inst->opcodes[i++] = opcode;
		line += 3;
	}
	inst->length = i;

	// more whitespace
	while((*line == ' ' || *line == '\t') && *line != '\0')
		++line;

	// check for error
	if(*line == '\0')
		return 0;

	// mnemonic
	i = 0;
	while(*line != ' ' && *line != '\0')
	{
		inst->mnemonic[i++] = *line++;
	}
	inst->mnemonic[i] = '\0';

	// more whitespace
	while((*line == ' ' || *line == '\t') && *line != '\0')
		++line;

	// check for error
	if(*line == '\0')
		return 0;

	// operand
	i = 0;
	while(*line != ' ' && *line != '\0')
	{
		inst->operands[i++] = *line++;
	}
	inst->operands[i] = '\0';

	return 1;
}

/**
 *  Populates an array of Instruction structs for a range of addresses within a binary image.
 *
 *  @param[in] file
 *      Object file containing the instructions
 *
 *  @param[in] address
 *      Offset within the image to start disassembly
 *
 *  @param[in] bytes
 *      The minimum number of bytes that must be covered by the instructions outputed.
 *
 *  @param[out] insns
 *      The instructions in the specified range.
 *
 */
int get_instructions(const char* file, void* address, int bytes, Instruction* insns)
{
	char start_addr[64];
	char stop_addr[64];

	snprintf(start_addr, sizeof(start_addr), "--start-address=0x%x", address);
	snprintf(stop_addr, sizeof(stop_addr), "--stop-address=0x%x", (intptr_t) address + bytes);

	int count = 0;
	char* disasm = get_command_output("/usr/bin/objdump", "/usr/bin/objdump", "-D", file, start_addr, stop_addr, NULL);
	char* disasmLine = strtok(disasm, "\n");        // TODO: Not thread-safe
	do
	{
		if(parse_objdump_asm(disasmLine, &insns[count]))
			++count;
	}
	while((disasmLine = strtok(NULL, "\n")) != NULL);

	free(disasm);

	insns[count].length = 0;

	return count;
}

/**
 *  Populates an array of Instruction structs for a range of addresses.
 *
 *  @param[in] address
 *      Buffer containing the instructions.
 *
 *  @param[in] bytes
 *      The minimum number of bytes that must be covered by the instructions outputed.
 *
 *  @param[out] insns
 *      The instructions in the specified range.
 *
 */
int get_instructions_from_memory(const void* address, int bytes, Instruction* insns)
{
	char tempFile[PATH_MAX];
	
	tmpnam(tempFile);

	FILE* f = fopen(tempFile, "w");
	fwrite(address, 1, bytes, f);
	fclose(f);

	int count = 0;
	char* disasm = get_command_output("/usr/bin/objdump", 
			"/usr/bin/objdump", "-m", "-i386", "-M", "x86-64", "-D", tempFile, NULL);

	unlink(tempFile);

	char* disasmLine = strtok(disasm, "\n");        // TODO: Not thread-safe
	do
	{
		if(parse_objdump_asm(disasmLine, &insns[count]))
			++count;
	}
	while((disasmLine = strtok(NULL, "\n")) != NULL);

	free(disasm);

	insns[count].length = 0;

	return count;
}

/**
 *  Interpose an AMD64 ABI function.
 *
 *  @param[in] dst
 *  	The address of the function to redirect calls to the target function to.
 *
 *  @param[in] address
 *  	The address of the function.
 *
 *  @return
 *  	The address of a trampoline function that may be called to perform the job of the uninterposed target.
 *  	NULL if the function could not be interposed.
 *
 */
//TODO: Use gnu as to make the image_path parameter unnecessary.
void* interpose_by_address64(void* dst, void* address)
{
	int page_size = sysconf(_SC_PAGE_SIZE);

	void* trampoline = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

	Instruction insns[32];
	int num_insns = get_instructions_from_memory(address, 14, insns);

	int i;
	char* trampoline_cursor = (char*) trampoline;
	for(i = 0; i < num_insns; i++)
	{
		// loop through and copy instructions to the trampoline one by one
		if(strstr(insns[i].operands, "%rip") != NULL
			|| strncmp(insns[i].mnemonic, "j", sizeof("j") - 1) == 0
			|| strncmp(insns[i].mnemonic, "call", sizeof("call") - 1) == 0
			|| strncmp(insns[i].mnemonic, "loop", sizeof("loop") - 1) == 0)
		{
			fprintf(stderr, "Error: PC dependent instruction at 0x%p: %s %s\n",
					insns[i].address, insns[i].mnemonic, insns[i].operands);

			munmap(trampoline, page_size);
			return NULL;
		}

		memcpy(trampoline_cursor, insns[i].opcodes, insns[i].length);
		trampoline_cursor += insns[i].length;
		
	}

	int copied_insns_size = (((uint64_t) trampoline_cursor) - ((uint64_t) trampoline));

	if(copied_insns_size < 14)
	{
		// Not enough room to put our jump.
		fprintf(stderr, "Error: Not enough room to add jump, only room for %d bytes.\n", copied_insns_size);
		munmap(trampoline, page_size);
		return NULL;
	}

	// Set the jump address to the original address + length of instructions already copied from original address
	*((uint64_t*)(((intptr_t) trampoline_cursor) + 6)) = ((uint64_t) address) + copied_insns_size;

	const char jmp[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};

	// Write the jmpq *0x0(%rip) instruction
	memcpy(trampoline_cursor, jmp, sizeof(jmp));

	// figure out what page the code we need to overwrite begins on
	void* target_page = (void*)(((intptr_t) address) & ~(page_size - 1));

	// unprotect two pages just to be safe (in case we straddle a page boundary)
	mprotect(target_page, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

	// write the jmp instruction at the beginning of the function
	memcpy(address, jmp, sizeof(jmp));

	// write destination address
	*((uint64_t*)(((intptr_t) address) + 6)) = (uint64_t) dst;

	// reprotect memory
	mprotect(target_page, page_size * 2, PROT_READ | PROT_EXEC);

	return trampoline;
}

/**
 *  Interpose an AMD64 ABI function.
 *
 *  @param[in] dst
 *  	The address of the function to redirect calls to the target function to.
 *
 *  @param[in] image_name
 *  	The name of the executable image_name that the target function can be found in. Blank for the main image.
 *
 *  @param[in] func
 *  	The name of the function to interpose. The function name must be found within the symbol table.
 *
 *  @return
 *  	The address of a trampoline function that may be called to perform the job of the uninterposed target.
 *  	NULL if the function could not be interposed.
 *
 */
void* interpose_by_name64(void* dst, const char* image_name, const char* func)
{
	void* address = find_function(getpid(), image_name, func, NULL);
	void* trampoline = interpose_by_address64(dst, address);
	return trampoline;
}

/**
 *  Uninterpose an AMD64 ABI function interposed by interpose64.
 *
 *  @param[in] trampoline
 *  	The address of the trampoline function returned by interpose64.
 *
 */
void uninterpose64(void* trampoline)
{
	const char jmp[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};
	int page_size = sysconf(_SC_PAGE_SIZE);

	char* after_addr = ((char*)trampoline) + 14 + sizeof(jmp);
	while(memcmp(after_addr - sizeof(jmp), jmp, sizeof(jmp)) != 0)
		++after_addr;

	int copied_insns_size = ((intptr_t)after_addr) - sizeof(jmp) - ((intptr_t)trampoline);
	void* orig_addr = (void*)(*((uint64_t*) after_addr) - copied_insns_size);

	void* target_page = (void*)(((intptr_t) orig_addr) & ~(page_size - 1));

	// unprotect two pages just to be safe (in case we straddle a page boundary)
	mprotect(target_page, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

	memcpy(orig_addr, trampoline, copied_insns_size);

	// reprotect memory
	mprotect(target_page, page_size * 2, PROT_READ | PROT_EXEC);

	munmap(trampoline, page_size);
}

