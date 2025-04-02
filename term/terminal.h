#ifndef XT_TERMINAL_H
#define XT_TERMINAL_H

#define XT_RELEASE_CODENAME "Cutler"
#define XT_RELEASE_DATE "2.5.2023"
#define XT_VERSION "1.5.0"

#include <stdbool.h>
#include <termios.h>

enum key_codes {
    KEY_NULL      = 0,
    KEY_CTRL_D    = 0x04,
    KEY_CTRL_H    = 0x08,
    KEY_CTRL_Q    = 0x11, // DC1, to exit the program.
    KEY_CTRL_R    = 0x12, // DC2, to redo an action.
    KEY_CTRL_S    = 0x13, // DC3, to save the current buffer.
    KEY_CTRL_U    = 0x15,
    KEY_ESC       = 0x1b, // ESC, for things like keys up, down, left, right, delete, ...
    KEY_ENTER     = 0x0d,
    KEY_BACKSPACE = 0x7f,
    KEY_TAB       = 0x09,
    KEY_CTRL_O    = 1000,
    KEY_INSERT,
    KEY_DELETE,
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_UP,
    KEY_DOWN,
    KEY_RIGHT,
    KEY_LEFT,
    KEY_DEL,
    KEY_HOME,
    KEY_END,
    KEY_PGUP,
    KEY_PGDOWN,
    KEY_CTRL_LEFT,
    KEY_CTRL_RIGHT,
    KEY_CTRL_ENTER,
    KEY_SHIFT_LEFT,
    KEY_SHIFT_RIGHT,
    KEY_SHIFT_ENTER,
    KEY_ESC_SHIFT_ENTER,
    KEY_ESC_SHIFT_LEFT_BRACKET,
    KEY_ESC_SHIFT_RIGHT_BRACKET
};

enum parse_errors {
    PARSE_SUCCESS,
    PARSE_INCOMPLETE_BACKSLASH,  // "...\"
    PARSE_INCOMPLETE_HEX,        // "...\x" or "...\xA"
    PARSE_INVALID_HEX,           // "...\xXY..." and X or Y not in [a-zA-Z0-9]
    PARSE_INVALID_ESCAPE,        // "...\a..." and a is not '\' or 'x'
};

void term_state_save();
void term_state_restore();
void enable_raw_mode();
void disable_raw_mode();
void clear_screen();
int  read_key();
int  hex2bin(const char* s);
void gotoxy(int rows, int cols);
bool get_window_size(int* rows, int* cols);
bool is_pos_num(const char* s);
bool is_hex(const char* s);
int hex2int(const char* s);
int clampi(int i, int min, int max);
int str2int(const char* s, int min, int max, int def);

#endif
