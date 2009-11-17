#ifndef ASM_H
#define ASM_H

typedef struct Instruction {
	void* address;
	int length;
	char opcodes[32];
	char mnemonic[16];
	char operands[64];
} Instruction;

int parse_objdump_asm(const char* line, Instruction* inst);
int get_instructions(const char* file, void* address, int bytes, Instruction* insns);
int get_instructions_from_memory(const void* address, int bytes, Instruction* insns);
void* interpose_by_address64(void* dst, void* address);
void* interpose_by_name64(void* dst, const char* image_name, const char* func);
void uninterpose64(void* trampoline);

#endif

