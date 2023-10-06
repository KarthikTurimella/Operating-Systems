////////////////////////////////////////////////////////
// Prototypes of all functions used in the kernel. 
// Access to any of these functions from a user process
// should happen via a system call
//

#include "lib.h"

/*** Debugging ***/
#define STOP	asm("cli\n hlt\n");

/*** Color codes ***/
#define BLACK		0x0
#define BLUE		0x1
#define GREEN		0x2
#define CYAN		0x3
#define RED		0x4
#define MAGENTA		0x5
#define BROWN		0x6
#define LIGHT_GRAY	0x7
#define DARK_GRAY	0x8
#define LIGHT_BLUE	0x9
#define LIGHT_GREEN	0xA
#define LIGHT_CYAN	0xB
#define LIGHT_RED	0xC
#define LIGHT_MAGENTA	0xD
#define YELLOW		0xE
#define WHITE		0xF


/*** A GDT entry ***/
typedef struct {
	uint16_t limit_0_15;	// segment limit bits 0:15
	uint16_t base_0_15;	// segment base bits 0:15
	uint8_t  base_16_23;	// segment base bits 16:23
	// access byte structure
	//  bit 7: set 1 (valid descriptor)
	//  bit 6 and 5: privilege level-0 for kernel, 3 for users
	//  bit 4: set 1 if code/data segment
	//  bit 3: set 1 if executable code in segment; else 0 for data
	//  bit 2: if data segment, set 0 (segment grows from
	//         base to base+limit)
	//         if code segment, set 0 to restrict access to
	//         privilege level
	//  bit 1: set 1 if code is readable/data is writable
	//  bit 0: set 1 by CPU when descriptor is accessed
	//  use 0x9A: for kernel (ring 0) code segment
	//  use 0x92: for kernel data segment
	//  use 0xFA: for user (ring 3) code segment
	//  use 0xF2: for user data segment
	//  use 0xE9: for task state segment (ring 3)
	uint8_t  access_byte;
	// flag structure (4 bits)
	// bit 0 and bit 1 are always 0
	// bit 3: set 1
	// bit 4: 1 means limit is in 4KB units; else 1byte unit
	uint8_t  limit_and_flag; // limit bits 16:19 (lower 4 bits) and flag
	uint8_t  base_24_31;	// base bits 24:31
} __attribute__ ((packed)) GDT_DESCRIPTOR;

/*** An IDT entry ***/
typedef struct {
	// bits 0-15 of interrupt handler address
	uint16_t handler_lo;
	// segment selector in GDT
	uint16_t sel;
	// reserved, should be 0
	uint8_t	reserved;
	// bit flags
	//   bit 7: set 1 (segment present)
	//   bit 6 and 5: privilege level-0 for kernel and 3 for users
	//   bit 4, 3, 2, 1: set 0b0111
	//   bit 0: set 0 for interrupt-gate, 1 for trap-gate
	uint8_t	flags;
	// bits 16-32 of interrupt handler address
	uint16_t handler_hi;
} __attribute__ ((packed)) IDT_DESCRIPTOR;

/*** A Task State Segment ***/
typedef struct tss_entry_struct
{
	uint32_t prev_tss;   
	uint32_t esp0;       // The stack pointer to load when we change to kernel mode
	uint32_t ss0;        // The stack segment to load when we change to kernel mode
	uint32_t esp1;       // everything below here is unusued now
	uint32_t ss1;
	uint32_t esp2;
	uint32_t ss2;
	uint32_t cr3;
	uint32_t eip;
	uint32_t eflags;
	uint32_t eax;
	uint32_t ecx;
	uint32_t edx;
	uint32_t ebx;
	uint32_t esp;
	uint32_t ebp;
	uint32_t esi;
	uint32_t edi;
	uint32_t es;         
	uint32_t cs;        
	uint32_t ss;        
	uint32_t ds;        
	uint32_t fs;       
	uint32_t gs;         
	uint32_t ldt;      
	uint16_t trap;
	uint16_t iomap_base;
} __attribute__ ((packed)) TSS_STRUCTURE;

/*** Process Control Block (everything about a process) ***/
typedef struct process_control_block {
	struct {
		uint32_t ss;         
		uint32_t cs;        
		uint32_t esp; 
		uint32_t ebp;      
		uint32_t eip;
		uint32_t eflags;
		uint32_t eax;
		uint32_t ebx;
		uint32_t ecx;
		uint32_t edx;
		uint32_t esi;
		uint32_t edi;
	} cpu;   

	uint32_t memory_base;
	uint32_t memory_limit;

} __attribute__ ((packed)) PCB;

/*** main.c ***/
int main(void);

/*** io.c ***/
void port_write_byte(uint16_t, uint8_t);
uint8_t port_read_byte(uint16_t);
uint16_t port_read_word(uint16_t);
void port_write_word(uint16_t, uint16_t);

/*** display.c ***/
void init_display(void);
void display_character(uint8_t);
void scroll_screen(void);
void cls(void);
void set_color(uint8_t, uint8_t);
uint8_t get_fcolor(void);
uint8_t get_bcolor(void);
void set_cursor(uint8_t, uint8_t);
void putc(char);
void puts(char *);
void putui(uint32_t);
void putsi(uint32_t);
void puth(uint32_t);
void sys_printf(const char *, ...);
void _printf(const char *, va_list, uint32_t);

/*** interrupts.c ***/
void handler_default_entry(void);
void default_interrupt_handler(void);
void install_interrupt_handler(int, void(*)(void), uint16_t, uint8_t);
void enable_interrupts(void);
void disable_interrupts(void);
void setup_IDT(void);
void setup_PIC(void);
void init_interrupts(void);

/*** systemcalls.c ***/
void setup_TSS(void);
void init_system_calls(void);
void handler_syscall_0XFF_entry(void);
void handler_syscall_0X94_entry(void);
__attribute__((fastcall)) void handler_syscall_0X94(void);
__attribute__((fastcall)) void handler_syscall_0XFF(void);

/*** exceptions.c ***/
void default_exception_handler(void);
void init_exceptions(void);

/*** kernelservices.c ***/
void execute_0x94(void);
void _0x94_getc(void);
void _0x94_printf(void);

/*** keyboard.c ***/
void handler_keyboard_entry(void);
void keyboard_interrupt_handler(void);
KEYCODE get_key(void);
bool get_CAPSLOCK_stat();
bool get_SHIFT_stat();
char sys_getc(void);
void init_keyboard(void);

/*** console.c ***/
void start_console(void);
char *read_command(char *, uint16_t *);
void command_diskdump(char *);
void command_run(char *);
uint8_t process_command(char *, uint16_t);

/*** disk.c ***/
void init_disk(void);
uint8_t read_disk(uint32_t, uint8_t, uint8_t *);

/*** memman.c ***/
void init_memory_manager(void);
void *alloc_memory(uint32_t);

/*** runprogram.c ***/
void run(uint32_t, uint32_t);
bool load_disk_to_memory(uint32_t, uint32_t, uint8_t *);
__attribute__((fastcall)) void switch_to_user_process(PCB *);

