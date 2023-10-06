#### Adapted from the Pintos Kernel Loader
#### This kernel code is loaded at 0x1000:0000 by the boot
#### loader in the MBR. The kernel runs all the way up to
#### 0x8FFF:0x000F, although much of it is not used. 

# We are still in 16-bit real mode
	.code16

# Get memory size
	xor %eax, %eax		# Clear unused upper bits not set by int 0x15
	movb $0x88, %ah
	int $0x15
	addl $1024, %eax	# Total kB memory
	cmp $0x10000, %eax	# Cap at 64 MB (we do no support more!)
	jbe 1f
	mov $0x10000, %eax
1:	#addr32 movl %eax, init_ram_pages - LOADER_PHYS_BASE - 0x20000
	addr32 movl %eax, total_memory
	
# Set string instructions to go upward.
	cld

#### Enable A20.  Address line 20 is tied low when the machine boots,
#### which prevents addressing memory about 1 MB.  This code fixes it.

# Poll status register while busy.

1:	inb $0x64, %al
	testb $0x2, %al
	jnz 1b

# Send command for writing output port.

	movb $0xd1, %al
	outb %al, $0x64

# Poll status register while busy.

1:	inb $0x64, %al
	testb $0x2, %al
	jnz 1b

# Enable A20 line.

	movb $0xdf, %al
	outb %al, $0x60

# Poll status register while busy.

1:	inb $0x64, %al
	testb $0x2, %al
	jnz 1b


#### Switch to protected mode.

# First, disable interrupts.  We won't set up the IDT until we get
# into C code, so any interrupt would blow us away.

	cli

# Protected mode requires a GDT, so point the GDTR to our GDT.
# We need a data32 prefix to ensure that all 32 bits of the GDT
# descriptor are loaded (default is to load only 24 bits).

	#data32 addr32 lgdt gdtdesc - LOADER_PHYS_BASE - 0x20000
	data32 addr32 lgdt gdtdesc

# Then we can turn on the following bits in CR0:
#    PE (Protect Enable): this turns on protected mode.
#    PG (Paging): turns on paging 
#    WP (Write Protect): if unset, ring 0 code ignores
#       write-protect bits in page tables (!).
#    EM (Emulation): forces floating-point instructions to trap.
#       We don't support floating point.

/* Flags in control register 0. */
#define CR0_PE 0x00000001      /* Protection Enable. */
#define CR0_EM 0x00000004      /* (Floating-point) Emulation. */
#define CR0_PG 0x80000000      /* Paging. */
#define CR0_WP 0x00010000      /* Write-Protect enable in kernel mode. */

	movl %cr0, %eax
	#orl $CR0_PE | CR0_PG | CR0_WP | CR0_EM, %eax
	orl $CR0_PE | CR0_EM, %eax
	movl %eax, %cr0

# We're now in protected mode in a 16-bit segment.  The CPU still has
# the real-mode code segment cached in %cs's segment descriptor.  We
# need to reload %cs, and the easiest way is to use a far jump.
# Because we're not running in a 32-bit segment the data32 prefix is
# needed to jump to a 32-bit offset in the target segment.

	# Kernel code segment selector = 0x08
	data32 ljmp $0x08, $begin_PM 

begin_PM:

# We're now in protected mode in a 32-bit segment.
# Let the assembler know.

	.code32

# Reload all the other segment registers to point into our new GDT
# Set up a stack for the kernel; we will set up a 16KB stack that 
# grows downward from 0x94000

	# Kernel data segment selector = 0x10
1:	movw $0x10, %ax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %fs
	movw %ax, %gs
	movw %ax, %ss
	#addl $LOADER_PHYS_BASE, %esp
	movl $0x94000, %eax
	movl %eax, %esp
	movl %esp, %ebp
 
	call main

# Returned from main (should never happen)
	cli
	hlt

#### GDT

	.align 8
# We will use a flat segmentation model
# Base and limit of user code/data descriptors should be 
# set before switching to a user taskg
.globl gdt
gdt:
	.quad 0x0000000000000000	# Null segment.  Not used by CPU
	.quad 0x00cf9a000000ffff	# Kernel code, base 0, limit 4 GB
	.quad 0x00cf92000000ffff        # Kernel data, base 0, limit 4 GB
	.quad 0x0000000000000000        # User code (set later when used)
	.quad 0x0000000000000000        # User data (set later when used)
	.quad 0x0000000000000000	# Task State Segment (set later in systemcalls.c)
gdtdesc:
	.word	gdtdesc - gdt - 1	# Size of the GDT, minus 1 byte.
	.long	gdt			# Address of the GDT.

#### Physical memory size in kB.  This is exported to the rest of the kernel.
.globl total_memory
total_memory:
	.long 0

