#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <execinfo.h>

#include <signal.h>

#include "util.h"
#include "asm.h"
#include "process.h"
#include "objdump.h"

static void* (*real_calloc)(size_t nmemb, size_t size);
static void* (*real_malloc)(size_t size);
static void (*real_free)(void* ptr);
static void* (*real_realloc)(void* ptr, size_t size);

static void** calloc_relocation;
static void** malloc_relocation;
static void** free_relocation;
static void** realloc_relocation;

typedef struct Backtrace
{
	int valid;
	int count;
	int refcount;
	void** addresses;
} Backtrace;

typedef struct Allocation
{
	int valid;
	void* address;
	size_t size;
	time_t logged;
	int backtrace;
} Allocation;

static int BacktraceCacheSize = 0;

static int AllocationCacheSize = 0;

static int ActiveBacktraces = 0;

static int ActiveAllocations = 0;

static Backtrace* BacktraceCache = NULL;

static Allocation* AllocationCache = NULL;

static int* AllocationCacheSorted = NULL;

static int NextFreeBacktraceCacheEntry = -1;

static int NextFreeAllocationCacheEntry = -1;

static time_t logging_started;
static time_t last_report;

static inline Allocation* GetFreeAllocation()
{
	Allocation* ret;

	// Handle the case of there being a free entry in the cache
	if(NextFreeAllocationCacheEntry != -1)
	{
		ret = &AllocationCache[AllocationCacheSorted[NextFreeAllocationCacheEntry]];
		++ActiveAllocations;

		// Point NextFreeAllocationCacheEntry to ANY free entries in the cache
		int orig = NextFreeAllocationCacheEntry;
		while((NextFreeAllocationCacheEntry = (NextFreeAllocationCacheEntry + 1) % AllocationCacheSize) != orig)
		{
			if(AllocationCache[AllocationCacheSorted[NextFreeAllocationCacheEntry]].valid == 0)
			{
				return ret;
			}
		}

		NextFreeAllocationCacheEntry = -1;
		return ret;
	}

	// There are no free entries currently in the cache, so extend it
	AllocationCache = (Allocation*) real_realloc(AllocationCache, sizeof(Allocation) * (AllocationCacheSize + 1));
	AllocationCache[AllocationCacheSize].valid = 0;
	ret = &AllocationCache[AllocationCacheSize];

	AllocationCacheSorted = (int*) real_realloc(AllocationCacheSorted, sizeof(int)
											* (AllocationCacheSize + 1));
	
	AllocationCacheSorted[AllocationCacheSize] = AllocationCacheSize;

	++AllocationCacheSize;

	++ActiveAllocations;

	return ret;
}

static inline Backtrace* GetFreeBacktrace()
{
	Backtrace* ret;

	// Handle the case of there being a free entry in the cache
	if(NextFreeBacktraceCacheEntry != -1)
	{
		ret = &BacktraceCache[NextFreeBacktraceCacheEntry];
		++ActiveBacktraces;

		// Point NextFreeBacktraceCacheEntry to ANY free entries in the cache
		int orig = NextFreeBacktraceCacheEntry;
		while((NextFreeBacktraceCacheEntry = (NextFreeBacktraceCacheEntry + 1) % BacktraceCacheSize) != orig)
		{
			if(BacktraceCache[NextFreeBacktraceCacheEntry].valid == 0)
			{
				return ret;
			}
		}

		NextFreeBacktraceCacheEntry = -1;
		return ret;
	}

	// There are no free entries currently in the cache, so extend it
	BacktraceCache = (Backtrace*) real_realloc(BacktraceCache, sizeof(Backtrace) * (BacktraceCacheSize + 1));
	BacktraceCache[BacktraceCacheSize].valid = 0;
	ret = &BacktraceCache[BacktraceCacheSize];

	++BacktraceCacheSize;

	++ActiveBacktraces;

	return ret;
}

// TODO: Add mutexs to the instrument entries so it's all thread-safe.

void instrument_malloc(void* ptr, size_t size)
{
	time_t action_time;
	time(&action_time);

	Allocation* entry = GetFreeAllocation();
	entry->valid = 1;
	entry->address = ptr;
	entry->size = size;
	entry->logged = action_time;

	// Get our backtrace
	void* bt_buffer[200];
	int nptrs = backtrace(bt_buffer, 200);

	// Try to find a backtrace that matches our current one
	int i;
	int bt_cursor;
	for(i = 0; i < BacktraceCacheSize; ++i)
	{
		if(BacktraceCache[i].valid != 1)
			continue;

		if(nptrs != BacktraceCache[i].count)
			continue;

		for(bt_cursor = 0; bt_cursor < nptrs; ++bt_cursor)
		{
			if(bt_buffer[bt_cursor] != BacktraceCache[i].addresses[bt_cursor])
				break;
		}

		if(bt_cursor == nptrs)
		{
			// we found a match, we can link our allocation to an existing backtrace
			++BacktraceCache[i].refcount;
			entry->backtrace = i;
			return;
		}
	}

	// if no backtrace match, a new entry must be made
	Backtrace* backtrace = GetFreeBacktrace();
	backtrace->valid = 1;
	backtrace->count = nptrs;
	backtrace->refcount = 1;
	backtrace->addresses = (void**) real_malloc(sizeof(void*) * nptrs);
	memcpy(backtrace->addresses, bt_buffer, sizeof(void*) * nptrs);

	entry->backtrace = backtrace - BacktraceCache;

	// yay, all done
}

void instrument_free(void* ptr)
{
	int i;

	Allocation* entry = NULL;

	// we need to find the Allocation this belongs to.
	for(i = 0; i < AllocationCacheSize; ++i)
	{
		if(AllocationCache[AllocationCacheSorted[i]].valid != 1)
			continue;

		if(AllocationCache[AllocationCacheSorted[i]].address == ptr)
		{
			entry = &AllocationCache[AllocationCacheSorted[i]];
			entry->valid = 0;
			NextFreeAllocationCacheEntry = i;	// Mark it as next while we know the index.
			--ActiveAllocations;
			break;
		}
	}

	if(!entry)
	{
		// Couldn't find an Allocation. Probably this belonged to something that was malloc'd before we were logging.
		return;
	}

	--BacktraceCache[entry->backtrace].refcount;

	if(BacktraceCache[entry->backtrace].refcount == 0)
	{
		// we need to free the backtrace too.
		real_free(BacktraceCache[entry->backtrace].addresses);
		BacktraceCache[entry->backtrace].valid = 0;
		NextFreeBacktraceCacheEntry = entry->backtrace;
		--ActiveBacktraces;
	}
}

static inline int partition_allocations_by_age(int left, int right, int pivotIndex)
{
	int pivot = AllocationCacheSorted[pivotIndex];

	if(AllocationCache[pivot].valid)
	{
		// only move anything to the left of pivot if pivot is valid

		// move pivot to the right
		AllocationCacheSorted[pivotIndex] = AllocationCacheSorted[right];
		AllocationCacheSorted[right] = pivot;

		int storeIndex = left;

		int i;
		for(i = left; i < right; ++i)
		{
			if(!AllocationCache[AllocationCacheSorted[i]].valid || // move to left if this is not valid
				AllocationCache[AllocationCacheSorted[i]].logged 
					>= AllocationCache[pivot].logged) // move to left if this is younger than pivot
			{
				int temp = AllocationCacheSorted[i];
				AllocationCacheSorted[i] = AllocationCacheSorted[storeIndex];
				AllocationCacheSorted[storeIndex] = temp;
				++storeIndex;
			}
		}

		// move pivot to its final place
		AllocationCacheSorted[right] = AllocationCacheSorted[storeIndex];
		AllocationCacheSorted[storeIndex] = pivot;

		return storeIndex;
	}
	else
	{
		// move pivot to the leftmost, since invalid entries always go on the left.
		AllocationCacheSorted[pivotIndex] = AllocationCacheSorted[left];
		AllocationCacheSorted[left] = pivot;

		return left;
	}
}

// This invalidates NextFreeAllocationCacheEntry!
static void sort_allocations_by_age(int left, int right)
{
	if(right > left)
	{
		int pivotIndex = partition_allocations_by_age(left, right, left);
		sort_allocations_by_age(left, pivotIndex - 1);
		sort_allocations_by_age(pivotIndex + 1, right);
	}
}

static const char* get_time_str(int secs)
{
	static char buf[100];
	char* cursor = buf;
	if(secs > (24 * 60 * 60))
	{
		int days = secs / (24 * 60 * 60);
		snprintf(cursor, sizeof(buf) - (cursor - buf), "%dd", days);
		cursor += strlen(cursor);
		secs -= days * (24 * 60 * 60);
	}
	if(secs > (60 * 60))
	{
		int hours = secs / (60 * 60);
		snprintf(cursor, sizeof(buf) - (cursor - buf), "%dh", hours);
		cursor += strlen(cursor);
		secs -= hours * (60 * 60);
	}
	if(secs > 60)
	{
		int minutes = secs / 60;
		snprintf(cursor, sizeof(buf) - (cursor - buf), "%dm", minutes);
		cursor += strlen(cursor);
		secs -= minutes * 60;
	}
	snprintf(cursor, sizeof(buf) - (cursor - buf), "%ds", secs);

	return buf;
}

void instrument_report()
{
	time_t now;
	time(&now);

	last_report = now;

	sort_allocations_by_age(0, AllocationCacheSize - 1);
	NextFreeAllocationCacheEntry = -1; // sorting invalidates NextFreeAllocationCacheEntry

	FILE* f = fopen("/tmp/malloc-log", "a");
	fprintf(f, "*** BEGIN REPORT: %s ***\n", get_time_str(now - logging_started));
	fprintf(f, "Peak allocations reached:\t%d\n", AllocationCacheSize);
	fprintf(f, "Peak backtraces reached:\t%d\n", BacktraceCacheSize);
	fprintf(f, "Active allocations:\t\t%d\n", ActiveAllocations);
	fprintf(f, "Active backtraces:\t\t%d\n", ActiveBacktraces);
	fprintf(f, "%-10s %-10s\t%s\n", "Age", "Size", "Backtrace");
	fprintf(f, "---------------------------------\n");
	int i;
	for(i = 0; i < AllocationCacheSize; i++)
	{
		Allocation* entry = &AllocationCache[AllocationCacheSorted[i]];
		if(entry->valid == 0)
		{
			if(NextFreeAllocationCacheEntry == -1)
				NextFreeAllocationCacheEntry = i;

			continue;
			//break;
		}
		
		// print age and size
		fprintf(f, "%-10s %-10lld\t", get_time_str(now - entry->logged), (long long)entry->size);

		// print backtrace
		Backtrace* bt = &BacktraceCache[entry->backtrace];
		int count = bt->count;
		int j;
		for(j = 0; j < count; ++j)
		{
			if(j != 0)
				fprintf(f, ", ");

			fprintf(f, "%p", bt->addresses[j]);
		}

		fprintf(f, "\n");
	}
	fprintf(f, "*** END REPORT ***\n");
	fclose(f);
}

static inline void check_should_report()
{
	time_t now;
	time(&now);

	if((now - last_report) >= ((0 * 24) + (0 * 3600) + (10 * 60)))
	{
		instrument_report();
	}
}

void* calloc_hook(size_t nmemb, size_t size)
{
	void* ret = real_calloc(nmemb, size);
	instrument_malloc(ret, nmemb * size);
	check_should_report();
	return ret;
}

void* malloc_hook(size_t size)
{
	void* ret = real_malloc(size);
	instrument_malloc(ret, size);	
	check_should_report();
	return ret;
}

void free_hook(void* ptr)
{
	instrument_free(ptr);
	real_free(ptr);
	check_should_report();
}

void* realloc_hook(void* ptr, size_t size)
{
	void* ret = real_realloc(ptr, size);
	instrument_free(ptr);
	instrument_malloc(ret, size);
	check_should_report();
	return ret;
}

void __attribute__ ((constructor)) interpose_init()
{
	time(&logging_started);
	last_report = logging_started;

	FILE* f = fopen("/tmp/malloc-log", "a");
	fprintf(f, "------ LOGGING STARTED ------\n");
	fclose(f);

	calloc_relocation = find_relocation(getpid(), "", "calloc");
	malloc_relocation = find_relocation(getpid(), "", "malloc");
	free_relocation = find_relocation(getpid(), "", "free");
	realloc_relocation = find_relocation(getpid(), "", "realloc");

	real_calloc = *calloc_relocation;
	real_malloc = *malloc_relocation;
	real_free = *free_relocation;
	real_realloc = *realloc_relocation;

	*calloc_relocation = calloc_hook;
	*malloc_relocation = malloc_hook;
	*free_relocation = free_hook;
	*realloc_relocation = realloc_hook;
}

void __attribute__ ((destructor)) interpose_fini()
{
	*calloc_relocation = real_calloc;
	*malloc_relocation = real_malloc;
	*free_relocation = real_free;
	*realloc_relocation = real_realloc;

	instrument_report();

	if(AllocationCache)
		free(AllocationCache);

	if(AllocationCacheSorted)
		free(AllocationCacheSorted);

	int i;
	for(i = 0; i < BacktraceCacheSize; ++i)
	{
		if(BacktraceCache[i].valid)
			free(BacktraceCache[i].addresses);
	}

	if(BacktraceCache)
		free(BacktraceCache);

	FILE* f = fopen("/tmp/malloc-log", "a");
	fprintf(f, "------ END ------\n");
	fclose(f);
}

