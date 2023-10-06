////////////////////////////////////////////////////////
// Functions to set up interrupts
// 

#include "kernel_only.h"

/*** Interrupt Descriptor Table ***/
// i86 systems have 256 interrupts (0-31 are reserved)
IDT_DESCRIPTOR IDT[256];

/*** The default interrupt handler ***/
// All handlers will have a similar structure.
// The steps to create a handler include:
//   1) "handler_default_entry" will become "handler_<device>_entry"
//   2) "call default_interrupt_handler\n" will become 
//      "call <device>_interrupt_handler\n"
//   3) implement void <device>_default_handler()
//   4) add "void handler_<device>_entry(void)" in types.h
//   5) use install_interrupt_handler to register the new handler
// 
//   See the keyboard.c for an example
asm ("handler_default_entry: \n"
	"pushl %ds\n"
	"pushl %es\n"
	"pushl %fs\n"
	"pushl %gs\n"
	"pushal\n"
	"call default_interrupt_handler\n"
	"popal\n"
	"popl %gs\n"
	"popl %fs\n"
	"popl %es\n"
	"popl %ds\n"
	"sti\n"
	"iretl\n"
);
void default_interrupt_handler() {
	puts("Unhandled interrupt!");
	// hardware interrupts that land here once will be masked forever
}

/*** Installs an interrupt handler for a given interrupt ***/
void install_interrupt_handler(int intr_no, void (*handler_entry_address)(void), uint16_t sel, uint8_t flags) {
	uint32_t handler_base = (uint32_t)handler_entry_address;

	// low 16 bits of handler address
	IDT[intr_no].handler_lo = (uint16_t)(handler_base & 0x0000FFFF); 
	// high 16 bits of handler address
	IDT[intr_no].handler_hi = (uint16_t)((handler_base >> 16) & 0x0000FFFF); 
	IDT[intr_no].sel = sel;
	IDT[intr_no].reserved = 0;
	IDT[intr_no].flags = flags;
} 

/*** Enable interrupts ***/
void enable_interrupts() {
	asm volatile ("sti");
}

/*** Disable interrupts ***/
void disable_interrupts() {
	asm volatile ("cli");
}

/*** Set up the Interrupt Descriptor Table ***/
void setup_IDT() {
	int i;

	// where does the IDT begin (base) and where does it end (base+limit)
	uint32_t base  = (uint32_t)(&IDT[0]);
	uint16_t limit = (uint16_t)(sizeof(IDT_DESCRIPTOR) * 256 - 1);
	// collapsing base and limit into one value
	uint64_t operand = limit | ((uint64_t) (uint32_t) base << 16); 

	// set up a default handler for each interrupt
	// we should install proper handlers as and when devices are initialized
	for (i=0; i<256; i++) {
		install_interrupt_handler(i,handler_default_entry,0x0008,0x8E);
	}

	// load IDT
	asm volatile ("lidt %0" : : "m" (operand));
}


/*** Set up the Programmable Interrupt Controller ***/
// The PIC notifies the processor about hardware interrupts
// Each PIC can handle 8 hardware interrupts (IRQs)
// We need to tell each PIC which IDT does the IRQs correspond to
void setup_PIC() {
	// Programmable Interrupt Controller port addresses
	// Master PIC control command: 0x20
	// Master PIC data register: 0x21
	// Slave PIC control command: 0xA0
	// Slave PIC data register: 0xA1

	// mask all interrupts on both PICs
	port_write_byte (0x21, 0xff);
	port_write_byte (0xA1, 0xff);

	// initialize master
	port_write_byte (0x20, 0x11); // ICW1: single mode, edge triggered, expect ICW4
	port_write_byte (0x21, 0x20); // ICW2: line IRQ0...7 -> IDT 32...39
	port_write_byte (0x21, 0x04); // ICW3: slave PIC on line IRQ2
	port_write_byte (0x21, 0x01); // ICW4: 8086 mode, normal EOI, non-buffered

	// initialize slave
	port_write_byte (0xA0, 0x11); // ICW1: single mode, edge triggered, expect ICW4
	port_write_byte (0xA1, 0x28); // ICW2: line IRQ0...7 -> IDT 40...47
	port_write_byte (0xA1, 0x02); // ICW3: slave ID is 2
	port_write_byte (0xA1, 0x01); // ICW4: 8086 mode, normal EOI, non-buffered

	// unmask interrupts we will use (clear bit)
  	port_write_byte (0x21, 0xfd); // keyboard (bit 1)

}

void init_interrupts() {
	setup_PIC();
	setup_IDT();

	// enable interrupts
	enable_interrupts();
}

