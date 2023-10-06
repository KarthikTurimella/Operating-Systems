////////////////////////////////////////////////////////
// Services provided by kernel via 0x94 system call
// 

#include "kernel_only.h"

extern PCB *current_process;

/*** Process the 0x94 system call ***/
// Context of calling process is in current_process
// EAX always has the system call number
void execute_0x94(void) {

	switch (current_process->cpu.eax) {
		case SYSCALL_GETC: _0x94_getc(); break;
		case SYSCALL_PRINTF: _0x94_printf(); break;
		default: sys_printf("No match"); break;
	}
}

/*** Return the keyboard scan code and SHIFT/CAPSLOCK status ***/
void _0x94_getc(void) {
	char key;

	enable_interrupts(); // okay to have other interrupts while waiting for key entry
	key = sys_getc();
	disable_interrupts();

	// returned in EDX register
	current_process->cpu.edx = (uint32_t)key;
}

/*** Print formatted output for the user ***/
void _0x94_printf(void) {
	char *format = (char *)current_process->cpu.ebx;
	va_list args = (va_list)current_process->cpu.ecx;

	// verify that parameter addresses are in process memory range
	if (current_process->cpu.ebx > current_process->memory_limit ||
		current_process->cpu.ecx > current_process->memory_limit) {
		current_process->cpu.edx = 0; // means error
		return;
	}

	_printf(format,args,current_process->memory_base);

	current_process->cpu.edx = 1; // success
}
