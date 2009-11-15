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
#include "util.h"
#include "asm.h"

void usage()
{
	printf("Usage:\n");
	printf("\tinject <pid> -i <.so file>\t\tInject a shared library into a process.\n");
	printf("\tinject <pid> -u <handle>\t\tRemove a shared library previously injected into a process.\n");
	printf("\n");
}

int main(int argc, const char* const argv[])
{
	if(argc < 4)
	{
		usage();
		exit(0);
	}

	int pid = atoi(argv[1]);

	if(strncmp(argv[2], "-i", 2) == 0)
	{
		printf("Injection returned handle: %x\n", inject_so(pid, argv[3]));
	}
	else if(strncmp(argv[2], "-u", 2) == 0)
	{
		void* handle;
		sscanf(argv[3], "%llx", &handle);
		printf("Uninjection returned: %d\n", uninject_so(pid, handle));
	}
	else
	{
		usage();
	}

	return 0;
}

