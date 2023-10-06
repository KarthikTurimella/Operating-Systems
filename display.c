////////////////////////////////////////////////////////
// Everything about writing to the display
//
//

#include "kernel_only.h"


extern uint32_t total_sectors;	// total number of sectors from disk.c
extern uint64_t total_memory;	// total RAM from startup.S

/*** Cursor position and video memory location ***/
uint8_t cursor_x;		// current cursor X position
uint8_t cursor_y;		// current cursor Y position
uint8_t color;			// current color
uint16_t *video_memory;		// pointer to video memory

/*** Initialize the display ***/
void init_display() {
	int i;
	cursor_x = 0;
	cursor_y = 0;
	video_memory = (uint16_t *)(0xB8000); 

	// show some art!
	set_color(WHITE,BLUE);
	for (i=0; i<80*8; i++) putc(' ');
	cursor_x = 0; cursor_y = 0;
	puts("     _______.  ______        _______.\n    /       | /  __  \\      /       |\n   |   (----`|  |  |  |    |   (----`\n    \\   \\    |  |  |  |     \\   \\    \n.----)   |   |  `--'  | .----)   |   \n|_______/     \\______/  |_______/\n\n\n");

	// display memory installed
	cursor_x = 55; cursor_y = 1;
	putui(total_memory);
	puts(" KB RAM\n");

	// display HDD size
	cursor_x = 55; cursor_y = 2;
	putui(total_sectors*512/1024);
	puts(" KB HDD\n");

	cursor_x = 0; cursor_y = 8;
	set_color(LIGHT_GRAY,BLACK);
	set_cursor(cursor_x,cursor_y);

        cls();
}

/*** Write a character at current cursor position ***/
// 2 bytes are written: <color> then <character>
void display_character(uint8_t c) {
	uint16_t attr = color << 8; // first byte is color
	uint16_t *loc = video_memory + (80*cursor_y + cursor_x);

	// backspace
	if (c == 0x08 && !(cursor_x==0 && cursor_y==8)) {
		if (cursor_x == 0) {
			cursor_x = 79;
			cursor_y --;
		}
		else
			cursor_x--;
		*(loc-1) = ' ' | attr;
	}
	// tab
	else if (c == 0x09) cursor_x = 8 * ((cursor_x+8)/8);
	// carriage return
	else if (c == '\r') cursor_x = 0;
	// new line
	else if (c == '\n') {
		cursor_x = 0;
		cursor_y++;
	}	
	// other characters
	else if(c >= 32) {
		*loc = c | attr;
		cursor_x++;
	}

	// edge conditions
	if (cursor_x >= 80) { // goto next line
		cursor_x = 0;
		cursor_y++;
	}
	if (cursor_y >= 25) { // scroll screen up
		scroll_screen();
	}

	set_cursor(cursor_x,cursor_y);
}

/*** Scroll the screen up by moving the contents up by one line ***/
// We reserve the top 8 lines for our beautiful logo!
void scroll_screen() {
	uint16_t attr = color << 8; // first byte is color
	int i;

	// move everything up one line, starting line 8
	for (i=8*80; i<24*80; i++) video_memory[i] = video_memory[i+80];

	// write blank on bottom line
	for (i=24*80; i<25*80; i++) video_memory[i] = attr | ' ';

	cursor_y = 24;

	set_cursor(cursor_x,cursor_y);
}

/*** Clear screen and reset cursor ***/
void cls() {
	uint16_t attr = color << 8; // first byte is color
	int i;
	
	// write blank on entire screen (except top 8 lines)
	for (i=8*80; i<25*80; i++) video_memory[i] = attr | ' ';

	cursor_x = 0;
	cursor_y = 8;

	set_cursor(cursor_x,cursor_y);
}	 

/*** Set foreground/background color ***/
void set_color(uint8_t foreground, uint8_t background) {
	color = (background << 4) | foreground ;
}

/*** Get foreground color ***/
uint8_t get_fcolor() {
	return(color & 0x0F);
}

/*** Get background color ***/
uint8_t get_bcolor() {
	return((color & 0xF0)>>4);
}

/*** Set the cursor ***/
void set_cursor(uint8_t x, uint8_t y) {
	uint16_t cursor_at = x + y*80;
	
	port_write_byte(0x3D4, 14);
	port_write_byte(0x3D5, cursor_at >> 8);	 // the high byte
	port_write_byte(0x3D4, 15);
	port_write_byte(0x3D5, cursor_at);	// the low byte
}

/*** Write a character ***/
void putc(char c) {
	display_character(c); 
}

/*** Write a character string ***/
void puts(char *s) {
	while (*s!=0) {
		putc(*s++);
	}
}

/*** Write a unsigned integer ***/
void putui(uint32_t n) {
	uint8_t d[20];
	int i=0;
	do {
		d[i++] = n % 10;
		n = n/10;
	} while(n!=0);
	for (i--; i>=0; i--)
		putc(d[i]+48); // ASCII code of '0' is 48
}

/*** Write a signed integer ***/
void putsi(uint32_t n) {
	if (n & 0x80000000) { // highest bit = 1 ==> negative
		putc('-');
		// signed integer stored in 2's complement format
		n = ~n + 0x1;	
	}
	putui(n);
}

/*** Write integer as hex string ***/
void puth(uint32_t n) {
	uint8_t d[8];
	int i=0;
	do {
		d[i++] = n % 16;
		n = n/16;
	} while(n!=0);
	for (i--; i>=0; i--)
		putc(d[i]+(d[i]<=9?48:55)); // ASCII code of '0' is 48, 'A' is 65
}

/*** Formatted output (simple printf) ***/
// Formatting strings:
//	%c: character
//	%s: string
//	%x: byte as hex
//	%u: unsigned integer
//	%d: signed integer
//	%%: %
//	%<any_other_character>: <any_other_character>
void sys_printf(const char *format, ...) {
	va_list args;

	va_start(args,format);
	_printf(format, (va_list)args, 0);
	va_end(args);
}
/*** Helper for above function ***/
// Offset lets us use addresses passed from user programs
void _printf(const char *format, va_list args, uint32_t offset) {
	int i=0;
	char c;

	format += offset;
	args += offset;

	while(format[i]!=0) {
		switch(format[i]) {
			case '%':
				if (format[++i]==0) break; // % was the last character
				switch(format[i]) {
					case 'c':	// character
						putc((char)va_arg(args,int)); break;

					case 's':	// string
						puts((char *)va_arg(args,int)+offset);
						break;

					case 'u':	// 32-bit unsigned integer
						putui(va_arg(args,int)); break;

					case 'd':	// 32-bit signed integer
						putsi(va_arg(args,int)); break;
	
					case 'x':	//  unsigned integer as hex
						puth(va_arg(args,int)); break;

					default:	// anything else 
						putc(format[i]); break;
				}
				break;
			
			default:	// no special formatting character
				putc(format[i]); break;
		}
		i++;
	}					
}




