////////////////////////////////////////////////////////
// Everything about reading from the keyboard
//
//

#include "kernel_only.h"

/*** Mapping scan codes to key codes ****/
static KEYCODE keymap[] = {
	//key		scancode
	KEY_UNKNOWN,	//0
	KEY_ESCAPE,	//1
	KEY_1,		//2
	KEY_2,		//3
	KEY_3,		//4
	KEY_4,		//5
	KEY_5,		//6
	KEY_6,		//7
	KEY_7,		//8
	KEY_8,		//9
	KEY_9,		//0xa
	KEY_0,		//0xb
	KEY_MINUS,	//0xc
	KEY_EQUAL,	//0xd
	KEY_BACKSPACE,	//0xe
	KEY_TAB,	//0xf
	KEY_Q,		//0x10
	KEY_W,		//0x11
	KEY_E,		//0x12
	KEY_R,		//0x13
	KEY_T,		//0x14
	KEY_Y,		//0x15
	KEY_U,		//0x16
	KEY_I,		//0x17
	KEY_O,		//0x18
	KEY_P,		//0x19
	KEY_LEFTBRACKET,//0x1a
	KEY_RIGHTBRACKET,//0x1b
	KEY_RETURN,	//0x1c
	KEY_UNKNOWN,	//0x1d
	KEY_A,		//0x1e
	KEY_S,		//0x1f
	KEY_D,		//0x20
	KEY_F,		//0x21
	KEY_G,		//0x22
	KEY_H,		//0x23
	KEY_J,		//0x24
	KEY_K,		//0x25
	KEY_L,		//0x26
	KEY_SEMICOLON,	//0x27
	KEY_QUOTE,	//0x28
	KEY_GRAVE,	//0x29
	KEY_LSHIFT,	//0x2a
	KEY_BACKSLASH,	//0x2b
	KEY_Z,		//0x2c
	KEY_X,		//0x2d
	KEY_C,		//0x2e
	KEY_V,		//0x2f
	KEY_B,		//0x30
	KEY_N,		//0x31
	KEY_M,		//0x32
	KEY_COMMA,	//0x33
	KEY_DOT,	//0x34
	KEY_SLASH,	//0x35
	KEY_RSHIFT,	//0x36
	KEY_UNKNOWN,    //0x37
	KEY_UNKNOWN,	//0x38
	KEY_SPACE,	//0x39
	KEY_CAPSLOCK,	//0x3a
};


KEYCODE current_key;	// key code of the current key
bool shift_on;		// is the SHIFT key in pressed state?
bool capslock_on;	// is the CAPS LOCK key on?

/*** The keyboard (IRQ1) handler ***/
asm("handler_keyboard_entry:\n"
	"pushal\n"
	"pushl %ds\n"
	"pushl %es\n"
	"pushl %fs\n"
	"pushl %gs\n"
	"call keyboard_interrupt_handler\n"
	"popl %gs\n"
	"popl %fs\n"
	"popl %es\n"
	"popl %ds\n"
	"popal\n"
	"sti\n"
	"iretl\n"
);
void keyboard_interrupt_handler() {
	// must reset the segment selectors before
	// accessing any kernel data
	asm volatile ("pushl $0x10\n" "pushl $0x10\n" "pushl $0x10\n" "pushl $0x10\n"
		      "popl %gs\n" "popl %fs\n" "popl %es\n" "popl %ds\n"); 

	uint8_t key;
	KEYCODE mapped_key;
	bool is_extended = FALSE;

	current_key = KEY_UNKNOWN;	// previous key press is discarded
	key = port_read_byte(0x60);	// read scan code from keyboard encoder
	
	if (key == 0xE1) { // two more bytes of extended scan code
		// read and discard (we do not support them)
		port_read_byte(0x60);
		port_read_byte(0x60);
		goto done;
	}
	else if (key == 0xE0) { // one more byte of extended scan code
		// we support the arrow keys only
		key = port_read_byte(0x60);
		is_extended = TRUE;
	}


	// Key press or key release?
	if (key & 0x80) {  
		// key release: scan code bit 7 is set when key press
		key &= 0x7F; 

		// Convert scan code to key code
		mapped_key = (key <= 0x3A)?keymap[key]:KEY_UNKNOWN;

		// only combination key we allow is SHIFT
		if (!is_extended &&
			(mapped_key == KEY_LSHIFT || mapped_key == KEY_RSHIFT))
			shift_on = FALSE;
	}

	else { // key press
		// is this one of the supported extended keys (arrow keys for us)
		if (is_extended) {
			switch(key) { // check arrow keys scan codes
				case 0x48: mapped_key = KEY_UP; break;
				case 0x4B: mapped_key = KEY_LEFT; break;
				case 0x50: mapped_key = KEY_DOWN; break;
				case 0x4D: mapped_key = KEY_RIGHT; break;
				default: mapped_key = KEY_UNKNOWN;
			}
			current_key = mapped_key;
			is_extended = FALSE;
		}
		else {
			mapped_key = (key <= 0x3A)?keymap[key]:KEY_UNKNOWN;

			// modifier key (SHIFT)
			if (mapped_key == KEY_LSHIFT || mapped_key == KEY_RSHIFT)
				shift_on = TRUE;
	
			// CAPSLOCK 
			else if (mapped_key == KEY_CAPSLOCK) {
				capslock_on = (capslock_on==TRUE)?FALSE:TRUE; // toggle 
				port_write_byte(0x60,0xED); // set LED command				
				port_write_byte(0x60,(capslock_on)<<2); // bit 2 is CAPSLOCK
			}

			else
				current_key = mapped_key;
				
		}
		
	}

done:				
			
	// the PIC masks interrupts when they are being serviced;
	// notify the PIC that interrupt has been serviced,
	// otherwise the interrupt will be ignored in future
	port_write_byte(0x20,0x20);	
}


/*** Get the last keycode ***/
KEYCODE get_key(void) {
	KEYCODE key = current_key;

	// key has been used
	current_key = KEY_UNKNOWN;

	return key;
}

/*** Status of SHIFT key ***/
bool get_SHIFT_stat() {
	return shift_on;
}

/*** Status of CAPS LOCK key ***/
bool get_CAPSLOCK_stat() {
	return capslock_on;
}

/*** Read a character from the keyboard ***/
// TODO: Modify so that you can return non ASCII characters also
char sys_getc(void) {
	bool shift_on ; 
	bool capslock_on;

	KEYCODE key = get_key();

	while (key==KEY_UNKNOWN
			|| key==KEY_LSHIFT || key==KEY_RSHIFT) { // control keys
		key = get_key();
	}

	capslock_on = get_CAPSLOCK_stat();
	shift_on = get_SHIFT_stat();

	if (key>='a' && key<='z') { // characters
		// make uppercase if shift is pressed or caps on
		if (shift_on || capslock_on) key -= 32;	
	}
	else if (shift_on) { // numbers and punctutations
		// apply key modifier
		switch(key) {
			case '0': key = ')'; break;
			case '1': key = '!'; break;
			case '2': key = '@'; break;
			case '3': key = '#'; break;
			case '4': key = '$'; break;
			case '5': key = '%'; break;
			case '6': key = '^'; break;
			case '7': key = '&'; break;
			case '8': key = '*'; break;
			case '9': key = '('; break;

			case '`': key = '~'; break;
			case '-': key = '_'; break;
			case '=': key = '+'; break;
			case '[': key = '{'; break;
			case ']': key = '}'; break;
			case '\\': key = '|'; break;
			case ';': key = ':'; break;
			case '\'': key = '"'; break;
			case ',': key = '<'; break;
			case '.': key = '>'; break;
			case '/': key = '?'; break;
		}
	}

	return (char)key;
}


/*** Initialize keyboard ***/
void init_keyboard() {
	// register keyboard handler
	// keyboard generates IRQ1, which is mapped to interrupt 33 (see setup_PIC)
	install_interrupt_handler(33,handler_keyboard_entry,0x0008,0x8E);

	current_key = KEY_UNKNOWN;	
	shift_on = FALSE;			
	capslock_on = FALSE;
	port_write_byte(0x60,0xED); // set LED command				
	port_write_byte(0x60,0x00); // bit 2 is CAPSLOCK (off)
}

