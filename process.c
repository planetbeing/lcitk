#define _FILE_OFFSET_BITS 64

#include "process.h"
#include "objdump.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#define __RTLD_DLOPEN 0x80000000

#if __WORDSIZE == 64
#define RETURN_REG(x) (x).rax
#define IP(x) (x).rip
#define SP(x) (x).rsp
#define SYSCALL_PARAM(x) (x).orig_rax
#else
#define RETURN_REG(x) (x).eax
#define IP(x) (x).eip
#define SP(x) (x).esp
#define SYSCALL_PARAM(x) (x).orig_eax
#endif

ssize_t pread64(int filedes, void *buffer, size_t size, off_t offset);

/**
 *  Reads bytes from the address space of a target process.
 *
 *  @param[in] process
 *  	The process PID to read from. The target process must not be attached to another process.
 *
 *  @param[out] buf
 *  	The buffer to read the bytes into.
 *
 *  @param[in] count
 *  	Number of bytes to read.
 *
 *  @param[in] addr
 *  	Address to read from. It must be mapped PROT_READ.
 *
 */
void process_read(int process, void* buf, size_t count, uintptr_t addr)
{
	char name[PATH_MAX];
	snprintf(name, sizeof(name), "/proc/%d/mem", process);

	int fd = open(name, O_RDONLY);
	
	if(fd == -1 || pread64(fd, buf, count, addr) == -1)
	{
		// Hmm, maybe we're not attached.
		if(ptrace(PTRACE_ATTACH, process, NULL, NULL) == -1)
		{
			// Guess that wasn't the problem.
			close(fd);
			return;
		}

		// Wait for process to stop. We need to have it stop before we do anything else.
		int status;
		waitpid(process, &status, 0);

		fd = open(name, O_RDONLY);
		pread64(fd, buf, count, addr);
		close(fd);

		ptrace(PTRACE_DETACH, process, NULL, NULL);
		return;
	}

	close(fd);
}

/**
 *  Write bytes to the address space of a target process, without regard to memory protection.
 *
 *  @param[in] process
 *  	The process PID to write to.
 *
 *  @param[in] buf
 *  	The buffer to write the bytes from.
 *
 *  @param[in] count
 *  	Number of bytes to write.
 *
 *  @param[in] addr
 *  	Address to write.
 *
 */
void process_write(int process, const void* buf, size_t count, uintptr_t addr)
{
	int do_detach = 0;
	// write word aligned data
	while(count >= sizeof(void*))
	{

		if(ptrace(PTRACE_POKEDATA, process, (void*)addr, (void*)(*((uintptr_t*)buf))) == -1)
		{
			if(ptrace(PTRACE_ATTACH, process, NULL, NULL) == -1)
			{
				// Guess that wasn't the problem.
				return;
			}

			// Wait for process to stop. We need to have it stop before we do anything else.
			int status;
			waitpid(process, &status, 0);

			ptrace(PTRACE_POKEDATA, process, (void*)addr, (void*)(*((uintptr_t*)buf)));
			do_detach = 1;
		}

		buf += sizeof(void*);
		addr += sizeof(void*);
		count -= sizeof(void*);
	}

	// write rest
	void* cur_word = (void*) ptrace(PTRACE_PEEKDATA, process, (void*)addr, NULL);
	if(errno != 0)
	{
		if(ptrace(PTRACE_ATTACH, process, NULL, NULL) == -1)
		{
			// Guess that wasn't the problem.
			return;
		}

		// Wait for process to stop. We need to have it stop before we do anything else.
		int status;
		waitpid(process, &status, 0);

		do_detach = 1;
	}

	memcpy(&cur_word, buf, count);
	ptrace(PTRACE_POKEDATA, process, (void*)addr, cur_word);

	if(do_detach)
		ptrace(PTRACE_DETACH, process, NULL, NULL);
}

/**
 *  Call a AMD64 ABI function with all INTEGER class arguments.
 *
 *  @param[in] process
 *  	The process's PID. The target process must not be attached to another process.
 *
 *  @param[in] function
 *  	The address of the function to call.
 * 
 *  @param[in] numargs
 *  	Number of parameters to pass into the function.
 *
 *  @return
 *  	Either the function return value or -1 for ptrace error (check errno if -1 is returned).
 *
 */
uintptr_t call_function_in_target(int process, void* function, int numargs, ...)
{
	uintptr_t* args = (uintptr_t*) malloc(sizeof(uintptr_t) * numargs);

	int i;
	va_list ap;
	va_start(ap, numargs);
	for(i = 0; i < numargs; i++)
	{
		args[i] = va_arg(ap, uintptr_t);
	}
	va_end(ap);

	uintptr_t ret = call_function_in_target_with_args(process, function, numargs, args);
	free(args);

	return ret;
}
	
/**
 *  Call a AMD64 ABI function with all INTEGER class arguments.
 *
 *  @param[in] process
 *  	The process's PID. The target process must not be attached to another process.
 *
 *  @param[in] function
 *  	The address of the function to call.
 * 
 *  @param[in] numargs
 *  	Number of parameters to pass into the function.
 *
 *  @return
 *  	Either the function return value or -1 for ptrace error (check errno if -1 is returned).
 *
 */
uintptr_t call_function_in_target_with_args(int process, void* function, int numargs, uintptr_t* args)
{
	uintptr_t ret = -1;
	int status;
	struct user_regs_struct regs, call_regs;

	const char breakpoint[] = {0xcc};	// int3, or the x86 breakpoint instruction.
						// Linux will signal us when our target hits it.
	
	char backup[sizeof(breakpoint)];	// instruction we overwrite with the breakpoint.

	if(ptrace(PTRACE_ATTACH, process, NULL, NULL) == -1)
		return -1;

	// Wait for process to stop. We need to have it stop before we do anything else.
	waitpid(process, &status, 0);

	// Back up the current prcoessor state as stored in the registers.
	if(ptrace(PTRACE_GETREGS, process, NULL, &regs) == -1)
		goto detach;

	// Back up the instructions at this location that we will overwrite with the breakpoint.
	process_read(process, backup, sizeof(backup), IP(regs));

	// Set our breakpoint
	process_write(process, breakpoint, sizeof(breakpoint), IP(regs));

	// Now we need to start setting up our call. We need to create a stack and register
	// situation that will reflect the state just after a call instruction, with the
	// return address as the real current rip.
	
	memcpy(&call_regs, &regs, sizeof(regs));

	// align stack to 8
	SP(call_regs) = (SP(call_regs) + 7) & ~(8 - 1);

#if __WORDSIZE == 64
	SP(call_regs) -= 128;	// Get past the 'red zone' allocated by amd64 abi
				// This appears to break stack unwinding via DWARF, unfortunately, but oh well

	// if after adding all the stack arguments, the stack pointer would not be 16 aligned, align it.
	// this is required by the AMD64 ABI.
	int stackargs = 0;
	if(numargs > 6)
		stackargs = numargs - 6;

	if((SP(call_regs) + (stackargs * 8)) & (16 - 1))
		SP(call_regs) += 8;
#endif

	// Loop through the arguments, assigning them to a register or pushing them onto the stack as appropriate.
	// We do this backwards because we need to push stack arguments in reverse order
	int i;
	uintptr_t cur_arg;
	for(i = (numargs - 1); i >= 0 ; --i)
	{
		cur_arg = args[i];
		switch(i)
		{
			// These register arguments only apply to AMD64
#if __WORDSIZE == 64
			case 0:
				call_regs.rdi = cur_arg;
				break;

			case 1:
				call_regs.rsi = cur_arg;
				break;

			case 2:
				call_regs.rdx = cur_arg;
				break;
			
			case 3:
				call_regs.rcx = cur_arg;
				break;

			case 4:
				call_regs.r8 = cur_arg;
				break;

			case 5:
				call_regs.r9 = cur_arg;
				break;
#endif
			default:
				// push this argument onto the stack
				SP(call_regs) -= sizeof(cur_arg);
				process_write(process, &cur_arg, sizeof(cur_arg), SP(call_regs));
		}
	}

#if __WORDSIZE == 64
	// Set the number of vector arguments to 0 for variable argument calls
	// This should affect "normal" calls.
	call_regs.rax = 0;
#endif

	// push return address onto the stack
	SP(call_regs) -= sizeof(cur_arg);
	process_write(process, &IP(regs), sizeof(IP(regs)), SP(call_regs));

	IP(call_regs) = (uintptr_t) function;
	if(SYSCALL_PARAM(regs) >= 0)
	{
		// we appear to have interrupted a system call.
		// prevent the kernel from attempting to reexecute the instruction that did the system call.
		// (right away at least, after we restore the original registers, the syscall will be retried)

		SYSCALL_PARAM(call_regs) = -1;
	}

	// Execute!
	ptrace(PTRACE_SETREGS, process, NULL, &call_regs);
	ptrace(PTRACE_CONT, process, NULL, NULL);

	// Wait for process to reach our set breakpoint, which indicates our function call has returned.
	do 
	{
		waitpid(process, &status, 0);
		printf("status: %d\n", WSTOPSIG(status));

		if(WIFSTOPPED(status))
		{
			// We're stopped, but is it at our breakpoint?
			if(WSTOPSIG(status) == SIGTRAP)
			{
				// Yes, continue.
				break;
			}
			else
			{
				if(WSTOPSIG(status) == SIGSEGV || WSTOPSIG(status) == SIGILL || WSTOPSIG(status) == SIGFPE)
				{
					// Our code screwed up the process. This is really really bad, but meh, most of
					// the time I think we can just restore state and pretend nothing ever happened.
					// Probably not too much memory got corrupted.
					
					fprintf(stderr,
						"Error: signal %d in attempted injection function call!\n", WSTOPSIG(status));

					ptrace(PTRACE_DETACH, process, NULL, NULL);
					exit(0);
					break;
				}

				// No, keep waiting for the right signal.
				ptrace(PTRACE_CONT, process, NULL, NULL);
			}
		}
	} while(1);

	// Save return value
	ptrace(PTRACE_GETREGS, process, NULL, &call_regs);
	ret = RETURN_REG(call_regs);

	// Restore the old instructions here
	process_write(process, backup, sizeof(backup), IP(regs));

	// Restore backed up registers
	ptrace(PTRACE_SETREGS, process, NULL, &regs);

detach:

	ptrace(PTRACE_DETACH, process, NULL, NULL);

	return ret;
}

/**
 *  Loads a shared object file into the specified process.
 *
 *  @param[in] process
 *  	The process's PID. The target process must not be attached to another process.
 *
 *  @param[in] filename
 *  	The full path of the .so file.
 *
 *  @return
 *  	Returns a handle to the dynamically loaded library, or NULL if there was any error.
 *
 */
void* inject_so(int process, const char* filename)
{
	// Get the full path of the file
	char resolved_path[PATH_MAX];
	char* path = realpath(filename, resolved_path);

	if(!path)
		return NULL;

	// Allocate room in the target process for the filename of the .so
	uintptr_t fileNameString =
		call_function_in_target(process, find_libc_function(process, "mmap"),
			6, 0, strlen(path) + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	// Write the filename of the .so into the target process
	process_write(process, path, strlen(path) + 1, fileNameString);

	// do dlopen
	uintptr_t ret = call_function_in_target(process, find_libc_function(process, "__libc_dlopen_mode"),
			2, fileNameString, RTLD_NOW | __RTLD_DLOPEN);
	
	// Free the filename of the .so
	call_function_in_target(process, find_libc_function(process, "munmap"), 2, fileNameString, strlen(path) + 1);

	return (void*) ret;
}

/**
 *  Unloads a shared object file from the specified process.
 *
 *  @param[in] process
 *  	The process's PID. The target process must not be attached to another process.
 *
 *  @param[in] handle
 *  	The handle returned by inject_so.
 *
 *  @return
 *  	0 on success, non-zero on error.
 *
 */
int uninject_so(int process, void* handle)
{
	// do dlclose
	return call_function_in_target(process, find_libc_function(process, "__libc_dlclose"),
			1, (uintptr_t) handle);
}


