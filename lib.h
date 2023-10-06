////////////////////////////////////////////////////////
// Library functions 
// Ideally you would have different files e.g. string.h,
// stdio.h, etc. 
// We will dump a few into this single file
//
// These functions can also be used by a user process

/*** Macros from GCC stdarg.h ***/
typedef __builtin_va_list va_list;
#define va_start(LIST,ARG) __builtin_va_start (LIST,ARG)
#define va_end(LIST) __builtin_va_end (LIST)
#define va_arg(LIST,TYPE) __builtin_va_arg (LIST,TYPE)

/*** Disk access error codes ***/
#define DISK_ERROR	0
#define DISK_ERROR_DF	1
#define DISK_ERROR_ERR	2
#define DISK_ERROR_SECTORCOUNT_TOO_BIG	2
#define DISK_ERROR_LBA_OUTSIDE_RANGE	3
#define NO_ERROR	0xFF

/*** INT 0x94 system call function ***/
#define SYSCALL_GETC	1
#define SYSCALL_PRINTF	2

#define NULL 0

typedef unsigned long long uint64_t;
typedef unsigned uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef enum {FALSE=0, TRUE=1} bool;

/*** Codes for the keyboard keys ***/
typedef enum {
	KEY_SPACE             = ' ',
	KEY_0                 = '0',
	KEY_1                 = '1',
	KEY_2                 = '2',
	KEY_3                 = '3',
	KEY_4                 = '4',
	KEY_5                 = '5',
	KEY_6                 = '6',
	KEY_7                 = '7',
	KEY_8                 = '8',
	KEY_9                 = '9',

	KEY_A                 = 'a',
	KEY_B                 = 'b',
	KEY_C                 = 'c',
	KEY_D                 = 'd',
	KEY_E                 = 'e',
	KEY_F                 = 'f',
	KEY_G                 = 'g',
	KEY_H                 = 'h',
	KEY_I                 = 'i',
	KEY_J                 = 'j',
	KEY_K                 = 'k',
	KEY_L                 = 'l',
	KEY_M                 = 'm',
	KEY_N                 = 'n',
	KEY_O                 = 'o',
	KEY_P                 = 'p',
	KEY_Q                 = 'q',
	KEY_R                 = 'r',
	KEY_S                 = 's',
	KEY_T                 = 't',
	KEY_U                 = 'u',
	KEY_V                 = 'v',
	KEY_W                 = 'w',
	KEY_X                 = 'x',
	KEY_Y                 = 'y',
	KEY_Z                 = 'z',

	KEY_DOT               = '.',
	KEY_COMMA             = ',',
	KEY_COLON             = ':',
	KEY_SEMICOLON         = ';',
	KEY_SLASH             = '/',
	KEY_BACKSLASH         = '\\',
	KEY_PLUS              = '+',
	KEY_MINUS             = '-',
	KEY_ASTERISK          = '*',
	KEY_EXCLAMATION       = '!',
	KEY_QUESTION          = '?',
	KEY_QUOTEDOUBLE       = '\"',
	KEY_QUOTE             = '\'',
	KEY_EQUAL             = '=',
	KEY_HASH              = '#',
	KEY_PERCENT           = '%',
	KEY_AMPERSAND         = '&',
	KEY_UNDERSCORE        = '_',
	KEY_LEFTPARENTHESIS   = '(',
	KEY_RIGHTPARENTHESIS  = ')',
	KEY_LEFTBRACKET       = '[',
	KEY_RIGHTBRACKET      = ']',
	KEY_LEFTCURL          = '{',
	KEY_RIGHTCURL         = '}',
	KEY_LESS              = '<',
	KEY_GREATER           = '>',
	KEY_BAR               = '|',
	KEY_GRAVE             = '`',
	KEY_TILDE             = '~',
	KEY_AT                = '@',
	KEY_CARRET            = '^',

	KEY_RETURN            = 0x0D,
	KEY_ESCAPE            = 0x1B,
	KEY_BACKSPACE         = 0x08,
	KEY_UP                = 0x1C,
	KEY_DOWN              = 0x1D,
	KEY_LEFT              = 0x1E,
	KEY_RIGHT             = 0x1F,
	KEY_TAB               = 0x09,
	KEY_CAPSLOCK          = 0x1001,
	KEY_LSHIFT            = 0x1002,
	KEY_RSHIFT            = 0x1003,
	KEY_UNKNOWN           = 0xFFFF
} KEYCODE;

/*** String related functions ***/
int strcmp(const char *, const char *);
int atoi(char *);

/*** I/O related functions ***/
char getc(void);
int printf(const char *, ...);
