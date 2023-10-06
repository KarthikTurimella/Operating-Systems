////////////////////////////////////////////////////////
// The SOS console
// Read commands and process them
// The console runs in kernel mode, but loaded 
// programs execute in user mode
//

#include "kernel_only.h"

char prompt[32] = {"% "};	// the command prompt

/*** Read a command from the console ***/
// Stores command in cmd_buffer and length in cmd_length
// Returns cmd_buffer
char *read_command(char *cmd_buffer, uint16_t *cmd_length) {
	char c;	
	*cmd_length = 0;

	puts(prompt);	// our prompt
	do {
		c = sys_getc();
		if (c == KEY_BACKSPACE) {
			// clear entered characters if possible
			if (*cmd_length > 0) {
				putc(c);
				cmd_buffer[*cmd_length-1] = 0;
				*cmd_length = *cmd_length - 1;
			}
		}

		else if (*cmd_length==512) continue;	// only allow 512 characters in a command

		else if (c != KEY_TAB && c != KEY_RETURN && // TODO: autocomplete on TAB
			c != KEY_UP && c != KEY_DOWN &&
			c != KEY_RIGHT && c != KEY_LEFT) { // TODO: command history using arrows	
			
			// display the character and store in buffer			
			putc(c);
			cmd_buffer[*cmd_length] = c;
			*cmd_length = *cmd_length + 1;
		}
	} while (c != KEY_RETURN);

	putc('\n');

	return cmd_buffer;
}

/*** Read command line input and process them ***/
void start_console(void) {
	char command_buffer[513]; // longest command length is 512 characters
	uint16_t command_length;
	uint8_t status;
	int i;

	while(1) {
		for (i=0; i<513; i++) command_buffer[i]=0; // clear command buffer
		read_command(command_buffer, &command_length);
		status = process_command(command_buffer,command_length);
		if (status == 0XFF) return; // shutdown command
	}
}

/*** Is a string a positive number? ***/
bool is_pos_number(char *s) {
	while ('0'<= *s && *s <= '9') s++;
	return ((*s==0 || *s==' ')?TRUE:FALSE); // end of string => number
}

/*** diskdump Command ***/
// Format: diskdump [start LBA] [sector count]
// Displays content of <sector count> number of sectors
// starting from <start LBA>
void command_diskdump(char *args) {
	uint8_t a_sector[512];
	uint8_t status;
	uint32_t LBA;
	uint32_t n_sectors;
	
	int i;
	
	// get start LBA
	if (*args==0 || *args==' ') {
		puts("Usage: diskdump [start LBA] [sector count]\n");
		return;
	}
	if (is_pos_number(args)==FALSE) {
		puts("diskdump: Invalid start LBA.\n");
		return;
	}
	LBA = atoi(args);

	// get sector count
	while (*args!=0 && *args!=' ') args++;	// goto end of first argument
	args++;					// second argument from next position
	if (*args==0 || *args==' ') {
		puts("Usage: diskdump [start LBA] [sector count]\n");
		return;
	}
	if (!is_pos_number(args)) {
		puts("diskdump: Invalid sector count.\n");
		return;
	}
	n_sectors = atoi(args);

	// read one sector at a time and display
	for (; n_sectors>0; n_sectors--,LBA++) {
		status = read_disk(LBA,1,a_sector);
		
		if (status == DISK_ERROR_LBA_OUTSIDE_RANGE
			|| status == DISK_ERROR_SECTORCOUNT_TOO_BIG) {
			puts("diskdump: LBA out of range.\n");
			return;
		}
		else if (status == DISK_ERROR || status == DISK_ERROR_ERR
				|| status == DISK_ERROR_DF) {
			puts("diskdump: Disk read error.\n");
			return;
		}
		// display the 512 bytes of the sector in hex notation
		for (i=0; i<512; i++) {
			sys_printf("%x%x ",a_sector[i]>>4,a_sector[i]&0x0F);
			if ((i+1)%16==0) putc('\n'); // new line every 16 bytes
		}
		puts("\n");
	}
}

/*** run Command ***/
// Format: run [start LBA] [sector count]
void command_run(char *args) {
	uint32_t LBA;
	uint32_t n_sectors;
	
	// get start LBA
	if (*args==0 || *args==' ') {
		puts("Usage: run [start LBA] [sector count]\n");
		return;
	}
	if (is_pos_number(args)==FALSE) {
		puts("run: Invalid start LBA.\n");
		return;
	}
	LBA = atoi(args);

	// get sector count
	while (*args!=0 && *args!=' ') args++;	// goto end of first argument
	args++;					// second argument from next position
	if (*args==0 || *args==' ') {
		puts("Usage: run [start LBA] [sector count]\n");
		return;
	}
	if (!is_pos_number(args)) {
		puts("run: Invalid sector count.\n");
		return;
	}
	n_sectors = atoi(args);
	if (n_sectors == 0) {
		puts("run: Invalid sector count.\n");
		return;
	}

	run(LBA,n_sectors);	// in runprogram.c
}

/*** Process a command typed by the user ***/
uint8_t process_command(char *cmd_buffer, uint16_t cmd_length) {
	char *cmd = cmd_buffer;
	char *args = cmd_buffer;
	uint16_t i;
	uint8_t status = 0; // success

	// separate command and arguments (if any)
	for (i=0; args[0]!=' ' && args[0]!=0; i++,args++);
	*args = 0; // command word ends here in the buffer
	if (i<cmd_length) args++; // arguments start next, if any

	// help
	if (strcmp(cmd,"help")==0) {
		if (*args != 0) puts("No such help available.\n");
		else puts("You are running a really Simple-OS.\n");
	}
	// cls: clear the screen
	else if (strcmp(cmd,"cls")==0) {
		if (*args != 0) puts("cls: What to do with the arguments?\n");
		else cls();
	}
	// shutdown
	else if (strcmp(cmd,"shutdown")==0) {
		if (*args != 0) puts("shutdown: What to do with the arguments?\n");
		else {
			puts("You really had to do that...SYSTEM HALTED!!\n");
			status = 0xFF; // halt the system
		}	
	}
	// diskdump: see disk content on screen
	else if (strcmp(cmd,"diskdump")==0) {
		command_diskdump(args);	
	}
	// run: run a program sequentially
	else if (strcmp(cmd,"run")==0) {
		command_run(args);	
	}
	// unknown command
	else if (cmd[0]!=0) {
		sys_printf("%s: Command not found.\n",cmd);
	}
	return status;
}



