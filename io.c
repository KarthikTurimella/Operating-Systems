////////////////////////////////////////////////////////
// Everything about hardware communication
//
//

#include "kernel_only.h"

/*** Write byte to port mapped device ***/
void port_write_byte (uint16_t port, uint8_t value) {
	asm volatile ("outb %b0, %w1" : : "a" (value), "Nd" (port));
}

/*** Read byte from port mapped device ***/
uint8_t port_read_byte (uint16_t port) {
	uint8_t value;
	asm volatile ("inb %w1, %b0" : "=a" (value) : "Nd" (port));
	return value;
}

/*** Read word (2 bytes) from port mapped device ***/
uint16_t port_read_word (uint16_t port) {
	uint16_t value;
	asm volatile ("inw %w1, %w0" : "=a" (value) : "Nd" (port));
	return value;
}

/*** Write word (2 bytes) to port mapped device ***/
void port_write_word (uint16_t port, uint16_t value) {
	asm volatile ("outw %w0, %w1" : : "a" (value), "Nd" (port));
}
