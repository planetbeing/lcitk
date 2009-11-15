/**
 * @file util.c
 * @author Your Mom
 *
 * A framework for injecting arbitrary code to interpose code within running Linux processes.
 *
 */

#define _FILE_OFFSET_BITS 64

#include "util.h"

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pwd.h>
#include <dirent.h>
#include <sys/stat.h>

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
char* get_command_output(const char* path, char* arg, ...)
{	
	va_list ap;
	char* argv[128];
	int argvIdx = 0;
	char* cur_arg;

	// Turn argument list into something execv can use
	va_start(ap, arg);
	for(cur_arg = arg; cur_arg != NULL; cur_arg = va_arg(ap, char*))
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
 *  Finds a process based on the name of its executable and/or the user it is running under.
 *
 *  @param[in] user
 *  	User name of the process to find. "-" for all users. If no user matches the name specified, the current
 *  	user will be used.
 *
 *  @param[in] name
 *  	The name of the executable image of the process.
 *
 *  @return
 *  	The pid of the process if found, 0 if not found.
 *
 */
int find_process(const char* user, const char* name)
{
	int bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	char* buf = (char*) malloc(bufsize);

	// figure out what the matching uid should be, either a number or -1 if *
	uid_t uid;
	if(user[0] == '-' && user[1] == '\0')
	{
		uid = -1;
	}
	else
	{
		struct passwd pwd;
		struct passwd* result;
		getpwnam_r(user, &pwd, buf, bufsize, &result);
		if(!result)
		{
			uid = getuid();
		}
		else
		{
			uid = result->pw_uid;
		}
	}

	struct dirent entry;

	// loop through everything in /proc
	int cur_process;
	int found = 0;
	DIR* procfs = opendir("/proc");
	while(1)
	{
		struct dirent* result;
		readdir_r(procfs, &entry, &result);
		if(result == NULL)
			break;

		// get pid in number form and check if this is actually a pid entry
		char* endptr;
		cur_process = strtol(result->d_name, &endptr, 10);
		if(*endptr != '\0')
			continue;

		// check for matching uid
		if(uid != -1)
		{
			snprintf(buf, bufsize, "/proc/%d", cur_process);
			struct stat file_stat;
			stat(buf, &file_stat);
			if(file_stat.st_uid != uid)
				continue;
		}

		// retrieve the path of the executable
		snprintf(buf, bufsize, "/proc/%d/exe", cur_process);
		char image_path_buf[PATH_MAX];
		char* image_path = realpath(buf, image_path_buf);
		if(!image_path)
			continue;

		// get the last component of the path
		char* last_sep = strrchr(image_path, '/');
		if(last_sep == NULL)
			last_sep = image_path;
		else
			++last_sep;

		if(strcmp(last_sep,  name) == 0)
		{
			found = cur_process;
			break;
		}
	}

	closedir(procfs);

	return found;
}

/**
 *  Finds a process based on a string specifier
 *
 *  @param[in] specifier
 *  	The specifier is in the format "( [<user>/]exec_name | pid )". <user> can be specified as '-' to
 *  	match all users (default behavior for root), otherwise only the current user's processes are searched.
 *
 *  @return
 *  	The pid of the process if found, 0 if not found.
 *
 */
int resolve_process(const char* specifier)
{
	int process;
	char* endptr;
	process = strtol(specifier, &endptr, 10);
	if(*endptr == '\0')
	{
		char buf[PATH_MAX];
		snprintf(buf, sizeof(buf), "/proc/%d", process);
		struct stat file_stat;
		if(stat(buf, &file_stat) == 0)
			return process;
		else
			return 0;
	}

	// determine whether a user field exists
	char* user = NULL;
	char* exec_name = NULL;
	char* buffer = strdup(specifier);
	char* sep = strchr(buffer, '/');
	if(sep)
	{
		// Yes. Separate the components
		exec_name = sep + 1;
		user = buffer;
		*sep = '\0';
	}
	else
	{
		// No. Use the whole specifier as process name to look for and search all users
		// when I'm root and just me if I'm not.
		exec_name = buffer;
		if(getuid() == 0)
			user = "-";
		else
			user = "";
	}

	// find the process
	process = find_process(user, exec_name);
	
	free(buffer);

	return process;
}

