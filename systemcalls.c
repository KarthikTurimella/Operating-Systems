////////////////////////////////////////////////////////
// Functions to set up system calls
// 

#include "kernel_only.h"

extern GDT_DESCRIPTOR gdt[6];	// from startup.S
extern PCB console;		// from runprogram.c
extern PCB *current_process;	// from runprogram.c

TSS_STRUCTURE TSS;	// the Task State Segment CPU will use during 
                  	// a system call


/*** The 0xFF system call handler ***/
// We will terminate the calling process and resume the 
// console
asm("handler_syscall_0XFF_entry:\n" 
	"movl %esp, %ecx\n"
	"jmp handler_syscall_0XFF\n"
);
__attribute__((fastcall)) void handler_syscall_0XFF(void) {
	// reload stack pointer (discards C function prologue)	
	asm volatile ("movl %ecx, %esp\n");
	// must reset the segment selectors before
	// accessing any kernel data
	asm volatile ("movl $0x10, %eax\n"
		      "movl %eax, %ds\n"
		      "movl %eax, %es\n"
		      "movl %eax, %fs\n"
		      "movl %eax, %gs\n");

	// we will restore the stack pointers to where it was before 
	// the user program was started
	asm volatile ("movl %0,%%esp\n"::"m"(console.cpu.esp)); 
	asm volatile ("movl %0,%%ebp\n"::"m"(console.cpu.ebp));
	// restore flags
	asm volatile ("pushl %0\n"::"m"(console.cpu.eflags));
	asm volatile ("popfl\n");	
	// we will continue execution in runprogram.c
	asm volatile ("sti\n");
	asm volatile ("jmp *%0\n": :"r" (console.cpu.eip));
}

/*** The 0x94 system call handler ***/
// This system call provides kernel services to user programs.
// The routines below saves the CPU state into the process's
// PCB, handles the system call, reloads the PCB and resumes
// execution of the user program. Return values are provided in
// the registers (see kernelservices.c)
asm("handler_syscall_0X94_entry: \n" // no interruption until done
	// we are using the kernel-mode stack (from TSS) of the
	// process; NOT the user's stack frame

	// CPU would have already pushed these in order:
	// SS, ESP, EFLAGS, CS and EIP of calling process
	// Push EAX, EBX, ECX, EDX (system call arguments)
	"pushal\n"
	"movl %esp, %ecx\n"
	"jmp handler_syscall_0X94\n"
);
__attribute__((fastcall)) void handler_syscall_0X94(void) {
	// reload stack pointer (discards C function prologue)	
	asm volatile ("movl %ecx, %esp\n");

	// must reset the segment selectors before
	// accessing any kernel data
	asm volatile ("movl $0x10, %eax\n"
		      "movl %eax, %ds\n"
		      "movl %eax, %es\n"
		      "movl %eax, %fs\n"
		      "movl %eax, %gs\n");

	// save CPU state in process PCB 
	asm volatile ("movl %%esp, %0\n": "=r"(current_process->cpu.edi));
	asm volatile ("movl 4(%%esp), %0\n": "=r"(current_process->cpu.esi));
	asm volatile ("movl 8(%%esp), %0\n": "=r"(current_process->cpu.ebp));
	asm volatile ("movl 16(%%esp), %0\n": "=r"(current_process->cpu.ebx));
	asm volatile ("movl 20(%%esp), %0\n": "=r"(current_process->cpu.edx));
	asm volatile ("movl 24(%%esp), %0\n": "=r"(current_process->cpu.ecx));
	asm volatile ("movl 28(%%esp), %0\n": "=r"(current_process->cpu.eax));
	asm volatile ("movl 32(%%esp), %0\n": "=r"(current_process->cpu.eip));
	asm volatile ("movl 36(%%esp), %0\n": "=r"(current_process->cpu.cs));
	asm volatile ("movl 40(%%esp), %0\n": "=r"(current_process->cpu.eflags));
	asm volatile ("movl 44(%%esp), %0\n": "=r"(current_process->cpu.esp));
	asm volatile ("movl 48(%%esp), %0\n": "=r"(current_process->cpu.ss));

	execute_0x94(); // handle system call (in kernelservice.c)

	switch_to_user_process(current_process);
}

/*** Set up the Task State Segment ***/
void setup_TSS(void) {
	int i;

	// zero out the TSS; TODO: use memset
	for (i=0; i<sizeof(TSS); i++) 
		*((uint8_t *)&TSS + i) = 0;

	// where does the TSS begin (base) and where does it end (base+limit)
	uint32_t base  = (uint32_t)&TSS;
	uint16_t limit = sizeof(TSS)-1; // 103 bytes

	// sixth GDT entry is for TSS; fill in the data
	gdt[5].base_0_15 = base & 0xFFFF;
	gdt[5].base_16_23 = (base >> 16) & 0xFF;
	gdt[5].base_24_31 = (base >> 24) & 0xFF;
	gdt[5].access_byte = 0xE9;
	gdt[5].limit_0_15 = limit & 0xFFFF;
	gdt[5].limit_and_flag = (uint8_t)((limit >> 16) & 0x0F) | 0x40;

	// load task register with GDT selector for TSS 
	asm volatile ("ltr %w0" : : "q" (0x2B)); // RPL = 3 (users can select it)
}

/*** Initialize system calls ***/
void init_system_calls(void) {
	setup_TSS();

	// 0xFF system call called by every program as the last instruction
	install_interrupt_handler(0xFF,handler_syscall_0XFF_entry,0x0008,0xEE); // DPL=3

	// 0x94 system call gives access to kernel services
	install_interrupt_handler(0x94,handler_syscall_0X94_entry,0x0008,0xEE); // DPL=3
}
