////////////////////////////////////////////////////////
// The DUMB Memory Manager
// 
// Allocates the same memory area to everyone

#include "kernel_only.h"

extern uint64_t total_memory;

uint32_t *alloc_base; // the returned memory base address
uint32_t total_memory_bytes; // max 64MB = 2^26 bytes

/*** Initialize memory manager ***/
void init_memory_manager(void) {
	total_memory_bytes = total_memory * 1024;

	// allocated memory always begins at 4MB mark
	alloc_base = (uint32_t *)(0x400000);
}

/*** Allocate count bytes of memory ***/
void *alloc_memory(uint32_t count) {
	int i;
	
	// check if we have the requested memory
	if ((uint32_t)alloc_base + count > total_memory_bytes)
		return NULL;
	// fill-zero the memory area; TODO: use memset	
	for (i=0; i<count; i++) 
		*((uint8_t *)alloc_base + i) = 0;

	return alloc_base;
}
