#### SOS kernel loader --- adapted from the Pintos Kernel Loader

#### This code should be stored in the first sector of a hard disk.
#### When the BIOS runs, it loads this code at physical address
#### 0x7c00-0x7e00 (512 bytes) and jumps to the beginning of it,
#### in real mode.  The loader loads the kernel into memory and jumps
#### to its entry point


# Runs in real mode, which is a 16-bit segment.
	.code16

# Set up a temporary stack for the kernel
	sub %ax, %ax
	mov %ax, %ss
	mov $0xf000, %esp

	call puts
	.string "Simple-OS"

#### Read the partition table on the first hard disk and scan for a
#### partition of type 0x10, which is the type that we use for a
#### SOS kernel.

	mov $0x80, %dl			# Hard disk 0.
	mov $0x07c0, %ax		# MBR loaded at 0x7c00
	mov %ax, %es
	mov $0x1be, %si			# Offset of partition table entry 1.

check_partition:
	# Is it an unused partition?
	cmpl $0, %es:(%si)
	je no_boot_partition

	# Is it a Simple-OS kernel partition?
	cmpb $0x10, %es:4(%si) 
	jne no_boot_partition

	jmp load_kernel

no_boot_partition:
	# Didn't find a Simple-OS kernel partition
	call puts
	.string "\rError: First partition entry is not for SOS.\r"

	# Notify BIOS that boot failed. 
	int $0x18

#### We found a kernel.  The kernel's drive is in DL.  The partition
#### table entry for the kernel's partition is at ES:SI.  Our job now
#### is to read the kernel from disk and jump to its start address.
#### SOS kernel is always loaded at address 0x10000

load_kernel:
	call puts
	.string "\rLoading"

	# SOS kernel is raw 512 KB stored in disk immediately after the MBR
	# 512 KB = 1024 sectors, starting at sector 1
	mov $1024, %ecx			# ECX = total number of sectors
	mov $1, %ebx			# EBX = first sector
	mov $0x1000, %ax		# Start load address: 0x1000:0x0000

next_sector:
	# Read one sector into memory.
	mov %ax, %es			# ES:0000 -> load address
	call read_sector
	jc read_failed

	# Print '.' as progress indicator once every 128 sectors == 64 kB.
	test $127, %bl
	jnz 1f
	call puts
	.string "."
1:
	# Advance memory pointer and disk sector.
	add $0x20, %ax
	inc %bx
	loop next_sector

	call puts
	.string "\r"

#### Transfer control to the kernel that we loaded at 0x1000:0000.
#### The 80x86 doesn't have an instruction to jump to an absolute segment:offset
#### kept in registers, so in fact we store the address in a temporary memory
#### location (kernel_load), then jump indirectly through that location.

	ljmp *kernel_load

kernel_load:
	.word 0x0000
	.word 0x1000

############
#### The following are helper subroutines used in the loader

#### Print error if unable to read a sector, and exit

read_failed:
	# Disk sector read failed.
	call puts
1:	.string "\rBad read\r"

	# Notify BIOS that boot failed.
	int $0x18

#### Print string subroutine.  To save space in the loader, this
#### subroutine takes its null-terminated string argument from the
#### code stream just after the call, and then returns to the byte
#### just after the terminating null.  This subroutine preserves all
#### general-purpose registers.

puts:	xchg %si, %ss:(%esp)
	push %ax
next_char:
	mov %cs:(%si), %al
	inc %si
	test %al, %al
	jz 1f
	call putc
	jmp next_char
1:	pop %ax
	xchg %si, %ss:(%esp)
	ret

#### Character output subroutine.  Prints the character in AL to the
#### VGA display, using BIOS services. Preserves all general-purpose registers.
####
#### If called upon to output a carriage return, this subroutine
#### automatically supplies the following line feed.

putc:	pusha

1:	sub %bh, %bh			# Page 0.
	mov $0x0e, %ah			# Teletype output service.
	int $0x10
2:
	cmp $'\r', %al
	jne popa_ret
	mov $'\n', %al
	jmp 1b

#### Sector read subroutine.  Takes a drive number in DL (0x80 = hard
#### disk 0, 0x81 = hard disk 1, ...) and a sector number in EBX, and
#### reads the specified sector into memory at ES:0000.  Returns with
#### carry set on error, clear otherwise.  Preserves all
#### general-purpose registers.

read_sector:
	pusha
	sub %ax, %ax
	push %ax			# LBA sector number [48:63]
	push %ax			# LBA sector number [32:47]
	push %ebx			# LBA sector number [0:31]
	push %es			# Buffer segment
	push %ax			# Buffer offset (always 0)
	push $1				# Number of sectors to read
	push $16			# Packet size
	mov $0x42, %ah			# Extended read
	mov %sp, %si			# DS:SI -> packet
	int $0x13			# Error code in CF
	popa				# Pop 16 bytes, preserve flags
popa_ret:
	popa
	ret				# Error code still in CF

#### Partition table --- a partition table entry
#### assuming that a SOS partition follows immediately. The start location
#### and length of the partition are left as 0. 
	.org 0x1BE
	.byte 0x80
	.word 0x0000
	.word 0x1000

#### Boot-sector signature for BIOS inspection.
	.org 0x1FE
	.word 0xaa55
