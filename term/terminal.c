#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "terminal.h"

static struct termios orig_termios;
char seq[4];

int hex2bin(const char* s) {
    int ret=0;
    for(int i = 0; i < 2; i++) {
        char c = *s++;
        int n=0;
        if( '0' <= c && c <= '9') n = c-'0';
        else if ('a' <= c && c <= 'f') n = 10 + c - 'a';
        else if ('A' <= c && c <= 'F') n = 10 + c - 'A';
        ret = n + ret*16;
    }
    return ret;
}

bool is_pos_num(const char* s) {
    for (const char* ptr = s; *ptr; ptr++) if (!isdigit(*ptr)) return false;
    return true;
}

bool is_hex(const char* s) {
    const char* ptr = s;
    while(*++ptr) if (!isxdigit(*ptr)) return false;
    return true;
}

int hex2int(const char* s) {
    char* endptr;
    intmax_t x = strtoimax(s, &endptr, 16);
    if (errno == ERANGE) return 0;
    return x;
}

inline int clampi(int i, int min, int max) {
    if (i < min) return min;
    if (i > max) return max;
    return i;
}

int str2int(const char* s, int min, int max, int def) {
    char* endptr;
    errno = 0;
    intmax_t x = strtoimax(s, &endptr, 10);
    if (errno  == ERANGE) return def;
    if (x < min || x > max) return def;
    return x;
}

int read_key() {
    int c = getchar();
    if (c == 27) { // Esc або стрілки
        int c2 = getchar();
        if (c2 == '[') {
            int c3 = getchar();
            if (c3 == 'A') return KEY_UP;    // Up
            if (c3 == 'B') return KEY_DOWN;  // Down
            if (c3 == 'C') return KEY_RIGHT; // Right
            if (c3 == 'D') return KEY_LEFT;  // Left
            if (c3 == 'H') return KEY_HOME;  // Home
            if (c3 == 'F') return KEY_END;   // End
            if (c3 == '3' && getchar() == '~') return KEY_DELETE;
            if (c3 == '5') { // PgUp
                getchar(); // ~
                return KEY_PGUP;
            }
            if (c3 == '6') { // PgDown
                getchar(); // ~
                return KEY_PGDOWN;
            } else if (c3 == '1' && getchar() == ';') { // Ctrl/Shift modifiers
                int c5 = getchar();
                if (c5 == '5') { // Ctrl
                    int c6 = getchar();
                    if (c6 == 'D') return KEY_CTRL_LEFT;  // Ctrl+Left: \033[1;5D
                    if (c6 == 'C') return KEY_CTRL_RIGHT; // Ctrl+Right: \033[1;5C
                } else if (c5 == '2') { // Shift
                    int c6 = getchar();
                    if (c6 == 'D') return KEY_SHIFT_LEFT;  // Shift+Left: \033[1;2D
                    if (c6 == 'C') return KEY_SHIFT_RIGHT; // Shift+Right: \033[1;2C
                }
            }
            // Обробка F1-F10
            if (c3 >= '1' && c3 <= '2') {
                int c4 = getchar();
                if (c3 == '1') {
                    if (c4 == '1') { getchar(); return KEY_F1; }  // F1: \033[11~
                    if (c4 == '2') { getchar(); return KEY_F2; }  // F2: \033[12~
                    if (c4 == '3') { getchar(); return KEY_F3; }  // F3: \033[13~
                    if (c4 == '4') { getchar(); return KEY_F4; }  // F4: \033[14~
                    if (c4 == '5') { getchar(); return KEY_F5; }  // F5: \033[15~
                    if (c4 == '7') { getchar(); return KEY_F6; }  // F6: \033[17~
                    if (c4 == '8') { getchar(); return KEY_F7; }  // F7: \033[18~
                    if (c4 == '9') { getchar(); return KEY_F8; }  // F8: \033[19~
                } else if (c3 == '2') {
                    if (c4 == '0') { getchar(); return KEY_F9; }  // F9: \033[20~
                    if (c4 == '1') { getchar(); return KEY_F10; } // F10: \033[21~
                    if (c4 == '~') { return KEY_INSERT; } // F10: \033[21~
                }
            }
        } else if (c2 == 'O') {
            int c3 = getchar();
            if (c3 == 'P') return KEY_F1;   // F1: \033OP
            if (c3 == 'Q') return KEY_F2;   // F2: \033OQ
            if (c3 == 'R') return KEY_F3;   // F3: \033OR
            if (c3 == 'S') return KEY_F4;   // F4: \033OS
        } else if (c2 >= 'A' && c2 <= 'Z') { // ESC + Shift
            int c3 = getchar();
            if (c2 == 'E' && c3 == '\n') return KEY_ESC_SHIFT_ENTER; // ESC+Shift+Enter
            if (c2 == '[') return KEY_ESC_SHIFT_LEFT_BRACKET; // ESC+Shift+[
            if (c2 == ']') return KEY_ESC_SHIFT_RIGHT_BRACKET; // ESC+Shift+]
        } else if (c2 == 27) {
            return KEY_ESC; // Esc
        } else {
            ungetc(c2, stdin); // Повернути символ назад
            return KEY_ESC;
        }
    } else if (c == '\n') {
        return KEY_ENTER;
    } else if (c == 9) {
        return KEY_TAB;
    } else if (c == 15) {
        return KEY_CTRL_O;
    } else if (c == 127) {
        return KEY_BACKSPACE;
    }
    return c;
}

bool get_window_size(int* rows, int* cols) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0) {
        perror("Failed to query terminal size");
        exit(1);
    }

    *rows = ws.ws_row;
    *cols = ws.ws_col;
    return true;
}

void term_state_save() {
    (void) (write(STDOUT_FILENO, "\x1b[?1049h", 8) + 1);
}

void term_state_restore() {
    (void) (write(STDOUT_FILENO, "\x1b[?1049l", 8) + 1);
}

void enable_raw_mode() {
    if (!isatty(STDIN_FILENO)) {
        perror("Input is not a TTY");
        exit(1);
    }

    tcgetattr(STDIN_FILENO, &orig_termios);

    struct termios raw = orig_termios;
    raw.c_iflag &= ~(IXON);
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
        perror("Unable to set terminal to raw mode");
        exit(1);
    }
}

void disable_raw_mode() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
    (void) (write(STDOUT_FILENO, "\x1b[?25h", 6) + 1);
}

void clear_screen() {
    char stuff[80];
    int bw = snprintf(stuff, 80, "\x1b[0m\x1b[H\x1b[2J");
    if (write(STDOUT_FILENO, stuff, bw) == -1) {
        perror("Unable to clear screen");
    }
}
