////////////////////////////////////////////////////////
// The main function of the SOS kernel
// It is called by startup.S after switching to
// 32-bit protected mode
//

#include "kernel_only.h"

/*** The beginning ***/
// Main is called from startup.S


int main(void) {
	
	init_disk();
	init_display();
	init_interrupts();	
	init_keyboard();
	init_system_calls();
	init_exceptions();
	init_memory_manager();
	
	start_console();

	return 0;
}
