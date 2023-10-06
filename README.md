# SOS

Week 3&4:
Ran user programs through the OS. (Ex. Test.c)
runprogram.c:
main purpose is to load and execute user programs.

Global Data Declarations: declarations for the Global Descriptor Table (GDT) and a Task State Segment (TSS)
Two PCBs: one for the console (kernel) and one for the currently running user program. Additionally, there's a pointer current_process pointing to the currently executing process's PCB.
run Function: Loads a user program from disk and executes it in user mode.
load_disk_to_memory Function: Reads data from a disk and loads it into memory. It reads sectors from the disk, checks for errors, and copies the data into a specified memory location.
switch_to_user_process Function: Switching to a user process. 
    Sets up the kernel-mode stack.
    Updates GDT entries for code and data segments.
    Loads CPU registers with values from the user program's PCB.
    Pushes values onto the stack.
    Sets up data segment selectors for user data segments.
    Executes the IRETL instruction to transition to user mode.
