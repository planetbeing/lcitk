/**
 * @file inject.c
 * @author Your Mom
 *
 * A framework for injecting arbitrary code to interpose code within running Linux processes.
 * This program uses LCITK to inject a shared library object into a running executable.
 *
 */

#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include "util.h"
#include "asm.h"
#include "objdump.h"
#include "process.h"

void usage()
{
	printf("Usage: inject ([<user>/]exec_name | pid) <option>\n");
	printf(" One of the following options must be given:\n");
	printf("   %-30s%s\n", "-i <.so file>", "Inject a shared library into a process.");
	printf("   %-30s%s\n", "-u (<.so file>|<handle>)", "Remove a shared library previously injected into a process.");
	printf("\n");
}

int main(int argc, const char* const argv[])
{
	if(argc < 4)
	{
		usage();
		exit(0);
	}

	int pid = resolve_process(argv[1]);

	if(strncmp(argv[2], "-i", 2) == 0)
	{
		printf("Injection returned handle: %x\n",
			(unsigned int)((intptr_t)inject_so(pid, argv[3])));
	}
	else if(strncmp(argv[2], "-u", 2) == 0)
	{
		char* endptr;
		void* handle = (void*) strtoll(argv[3], &endptr, 16);
		if(*endptr == '\0')
		{
			// "handle" argument, use directly.
			printf("Uninjection returned: %d\n", uninject_so(pid, handle));
		}
		else
		{
			// first, make sure the image is loaded. We do this by attempting
			// find the load address of the full path of the .so inside the
			// process's memory.
			char resolved_path[PATH_MAX];
			char* path = realpath(argv[3], resolved_path);
			if(!path)
			{
				fprintf(stderr, "Cannot find %s to uninject!\n", argv[3]);
				return 1;
			}

			char image_out_path[PATH_MAX];
			intptr_t image_start;
			if(find_image_address(pid, path, image_out_path, &image_start))
			{
				void* handle = inject_so(pid, path);

				// get rid of the reference we just made
				uninject_so(pid, handle);

				// get rid of the first injection's reference, hopefully
				printf("Uninjection returned: %d\n", uninject_so(pid, handle));
			}
			else
			{
				printf("The file %s is not loaded in proess %d.\n", path, pid);
			}
		}
	}
	else
	{
		usage();
	}

	return 0;
}

