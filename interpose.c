#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "asm.h"

char* cur_buffer = 0;
size_t cur_buffer_size = 0;

ssize_t (*real_write)(int fd, const void* buf, size_t count) = NULL;
ssize_t (**relocation)(int fd, const void* buf, size_t count) = NULL;

const char riverdale[]  = "Riverdale";

ssize_t fake_write(int fd, const void* buf, size_t count)
{
	if(count > cur_buffer_size)
	{
		cur_buffer_size = count;
		cur_buffer = (char*) realloc(cur_buffer, count);
	}

	int matchIdx = 0;
	int i;
	for(i = 0; i < count; i++)
	{
		cur_buffer[i] = ((char*)buf)[i];
		if(riverdale[matchIdx] == cur_buffer[i])
		{
			++matchIdx;
			if(matchIdx == (sizeof(riverdale) - 1))
			{
				cur_buffer[i - 3] = 'f';
				cur_buffer[i - 2] = 'a';
				cur_buffer[i - 1] = 'i';
				cur_buffer[i] = 'l';
				matchIdx = 0;
			}
		}
		else
		{
			matchIdx = 0;
		}
	}

	return write(fd, cur_buffer, count);
}

void (*real_do_loop)();

void do_loop_interpose()
{
	printf("Interposed!\n");
	real_do_loop();
}

void __attribute__ ((constructor)) interpose_init()
{
	real_do_loop = interpose_by_name64(&do_loop_interpose, "", "do_loop");
	//relocation = find_relocation(getpid(), "", "write");	
	//real_write = *relocation;
	//*relocation = fake_write;
}

void __attribute__ ((destructor)) interpose_fini()
{
	printf("uninterposing...\n");
	uninterpose64(real_do_loop);
	printf("removed.\n");
	//*relocation = real_write;
}
