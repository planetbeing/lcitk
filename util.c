/**
 * @file util.c
 * @author Your Mom
 *
 * A framework for injecting arbitrary code to interpose code within running Linux processes.
 *
 */

#define _FILE_OFFSET_BITS 64

#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/**
 *  For the specified command line, return a malloc'd string containing the stdout of the command when executed.
 *
 *  @param[in] path
 *  	The command's path.
 *
 *  @param[in] arg
 *  	The arguments to pass to the command. The list must be terminated by NULL.
 *
 *  @return
 *  	The stdout of the command. free() may be called with it when done.
 *
 */
char* get_command_output(const char* path, const char* arg, ...)
{	
	va_list ap;
	const char* argv[128];
	int argvIdx = 0;
	const char* cur_arg;

	// Turn argument list into something execv can use
	va_start(ap, arg);
	for(cur_arg = arg; cur_arg != NULL; cur_arg = va_arg(ap, const char*))
	{
		argv[argvIdx++] = cur_arg;
		if(argvIdx == 127)
			break;
	}
	va_end(ap);

	argv[argvIdx] = NULL;

	// Create pipe
	int stdout_pipe[2];
	pipe(stdout_pipe);

	// Create child
	pid_t pid = fork();
	if(pid == 0)
	{
		close(stdout_pipe[0]);
		dup2(stdout_pipe[1], 1);
		execv(path, argv);
		exit(0);
	}

	// Read child output
	close(stdout_pipe[1]);

	FILE* childStdout = fdopen(stdout_pipe[0], "r");

	char* retval = NULL;
	size_t retvalLen = 0;

	char buf[4096];
	size_t hasRead;
	while((hasRead = fread(buf, 1, sizeof(buf), childStdout)) != 0)
	{
		retval = (char*) realloc(retval, retvalLen + hasRead + 1);
		memcpy(retval + retvalLen, buf, hasRead);
		retvalLen += hasRead;
	}
	fclose(childStdout);

	if(retval)
		retval[retvalLen] = '\0';

	// Wait for child process to prevent zombies
	int status;
	waitpid(pid, &status, 0);

	return retval;
}

/**
 *  Unloads a shared object file from the specified process.
 *
 *  @param[in] process
 *  	The process's PID. The target process must not be attached to another process.
 *
 *  @param[in] name
 *  	The name of the process
 *
 *  @return
 *  	0 on success, non-zero on error.
 *
 */
int find_process(const char* user, const char* name)
{
}	
