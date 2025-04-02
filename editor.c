// BE: INFOSEC BINARY HEX EDITOR WITH DASM
// Synrc Research (c) 2022-2023
// 5HT DHARMA License

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>

#include "dasm/dasm.h"
#include "hex/hex.h"
#include "term/terminal.h"
#include "editor.h"

char* contents;
int content_length = 0;
static struct editor* e;

struct editor* editor() {
    return e;
}

struct editor* editor_init() {
    e = malloc(sizeof(struct editor));
    e->octets_per_line = 24;
    e->seg_size = 64;
    e->line = 0;
    e->cursor_x = 1;
    e->cursor_y = 1;
    e->filename = NULL;
    e->contents = NULL;
    e->content_length = 0;
    e->dirty = false;
    e->offset_dasm = 0;
    e->mode = MODE_NORMAL;
    e->view = VIEW_HEX;
    e->arch = ARCH_INTEL;
    e->inputbuffer_index = 0;
    memset(e->status_message, '\0', sizeof(e->status_message));
    memset(e->inputbuffer, '\0', sizeof(e->inputbuffer));
    memset(e->searchstr, '\0', sizeof(e->searchstr));
    get_window_size(&(e->screen_rows), &(e->screen_cols));
    return e;
}

int editor_parse_search_string(const char* inputstr, struct charbuf* parsedstr, const char** err_info)
{
    char hex[3] = {'\0'};
    *err_info = inputstr;
    while (*inputstr != '\0') {
        if (*inputstr == '\\') {
            ++inputstr;
            switch (*(inputstr)) {
                case '\0': return PARSE_INCOMPLETE_BACKSLASH;
                case '\\': charbuf_append(parsedstr, "\\", 1); ++inputstr; break;
                case 'x': ++inputstr;
                          int off = 0;
                          if (*inputstr == '\0' || *(inputstr + 1) == '\0') return PARSE_INCOMPLETE_HEX;
//                          while (*inputstr != '\0' && isxdigit(*inputstr + off)) {
  //                            off++;
    //                      }
//                          printf("OK\n");
//                          if (off < 2) {
                          if (!isxdigit(*inputstr) || !isxdigit(*(inputstr + 1))) {
                              *err_info = inputstr;
                              return PARSE_INVALID_HEX;
                          }
                          memcpy(hex, inputstr, 2);
                          char bin = hex2bin(hex);
                          charbuf_append(parsedstr, &bin, 1);
                          inputstr += 2;
                          break;
                default: *err_info = inputstr; return PARSE_INVALID_ESCAPE;
            }
        } else {
            charbuf_append(parsedstr, inputstr, 1);
            ++inputstr;
        }
    }
    return PARSE_SUCCESS;
}

void editor_process_search(struct editor* e, const char* str, enum search_direction dir) {
    struct charbuf *parsedstr = NULL;
    const char* parse_err;
    int parse_errno = 0;

    parsedstr = charbuf_create();
    if (strncmp(str, "", INPUT_BUF_SIZE) == 0) {
        strncpy(e->searchstr, str, INPUT_BUF_SIZE);
        return;
    }

    if (strncmp(str, e->searchstr, INPUT_BUF_SIZE) != 0) strncpy(e->searchstr, str, INPUT_BUF_SIZE);

    if (dir == SEARCH_BACKWARD && editor_offset_at_cursor(e) == 0) {
        editor_statusmessage(e, STATUS_INFO, "Already at start of the file");
        return;
    }

    parse_errno = editor_parse_search_string(str, parsedstr, &parse_err);
    switch (parse_errno) {
        case PARSE_INCOMPLETE_BACKSLASH:
             editor_statusmessage(e, STATUS_ERROR, "Nothing follows '\\' in search string: %s", str); break;
        case PARSE_INCOMPLETE_HEX:
             editor_statusmessage(e, STATUS_ERROR, "Incomplete hex value at end of search string: %s", str); break;
        case PARSE_INVALID_HEX:
             editor_statusmessage(e, STATUS_ERROR, "Invalid hex value (\\x%c%c) in search string: %s", *parse_err, *(parse_err + 1), str); break;
        case PARSE_INVALID_ESCAPE:
             editor_statusmessage(e, STATUS_ERROR, "Invalid character after \\ (%c) in search string: %s", *parse_err, str); break;
        case PARSE_SUCCESS: break;
    }

    if (parse_errno != PARSE_SUCCESS) {
        charbuf_free(parsedstr);
        return;
    }

    unsigned int current_offset = editor_offset_at_cursor(e);
    bool found = false;
    if (dir == SEARCH_FORWARD) {
        current_offset++;
        for (; current_offset < e->content_length; current_offset++) {
            if (memcmp(e->contents + current_offset, parsedstr->contents, parsedstr->len) == 0) {
                editor_statusmessage(e, STATUS_INFO, "");
                editor_scroll_to_offset(e, current_offset);
                found = true;
                break;
            }
        }
    } else if (dir == SEARCH_BACKWARD) {
        current_offset--;
        for (; current_offset-- != 0; ) {
            if (memcmp(e->contents + current_offset, parsedstr->contents, parsedstr->len) == 0) {
                editor_statusmessage(e, STATUS_INFO, "");
                editor_scroll_to_offset(e, current_offset);
                found = true;
                break;
            }
       }
    }

    charbuf_free(parsedstr);
    if (!found) editor_statusmessage(e, STATUS_WARNING, "String not found: '%s'", str);
}

void editor_newfile(struct editor* e, const char* filename) {
    e->filename = malloc(strlen(filename) + 1);
    e->contents = malloc(0);
    e->content_length = 0;
    strncpy(e->filename, filename, strlen(filename) + 1);
}

void editor_openfile(struct editor* e, const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        if (errno == ENOENT) {
            editor_newfile(e, filename);
            return;
        }
        perror("Unable to open file");
        exit(1);
    }

    struct stat statbuf;
    if (stat(filename, &statbuf) == -1) {
        perror("Cannot stat file");
        exit(1);
    }

    if (!S_ISREG(statbuf.st_mode)) {
        fprintf(stderr, "File '%s' is not a regular file\n", filename);
        exit(1);
    }


    if (statbuf.st_size <= 0) {
        struct charbuf* buf = charbuf_create();
        int c;
        char tempbuf[1];
        while ((c = fgetc(fp)) != EOF) { tempbuf[0] = (char) c; charbuf_append(buf, tempbuf, 1); }
        contents = buf->contents;
        content_length = buf->len;
    } else {
        contents = malloc(sizeof(char) * statbuf.st_size);
        content_length = statbuf.st_size;

        if (fread(contents, 1, statbuf.st_size, fp) < (size_t) statbuf.st_size) {
            perror("Unable to read file contents");
            free(contents);
            exit(1);
        }
    }

    e->filename = malloc(strlen(filename) + 1);
    strncpy(e->filename, filename, strlen(filename) + 1);
    e->contents = contents;
    e->content_length = content_length;

    if (access(filename, W_OK) == -1) {
        editor_statusmessage(e, STATUS_WARNING, "\"%s\" (%d bytes) [readonly]", e->filename, e->content_length);
    } else {
//		editor_statusmessage(e, STATUS_INFO, "\"%s\" (%d bytes)", e->filename, e->content_length);
//		editor_statusmessage(e, STATUS_INFO, "Terminal: %ix%i.", e->screen_cols, e->screen_rows);
//		editor_statusmessage(e, STATUS_INFO, "Views: press [a] for assembly view, [x] for hex view. ");
    }

    fclose(fp);
}

void editor_writefile(struct editor* e) {
    assert(e->filename != NULL);

    FILE* fp = fopen(e->filename, "wb");
    if (fp == NULL) {
        editor_statusmessage(e, STATUS_ERROR, "Unable to open '%s' for writing: %s", e->filename, strerror(errno));
        return;
    }

    size_t bw = fwrite(e->contents, sizeof(char), e->content_length, fp);
    if (bw <= 0) {
        editor_statusmessage(e, STATUS_ERROR, "Unable write to file: %s", strerror(errno));
        return;
    }

    editor_statusmessage(e, STATUS_INFO, "\"%s\", %d bytes written", e->filename, e->content_length);
    e->dirty = false;

    fclose(fp);
}

void editor_setview(struct editor* e, enum editor_view view) {
    if (e->view == view) return;
    e->view = view;
    switch (e->view) {
        case VIEW_ASM:
            e->offset_dasm = editor_offset_at_cursor(e);
            e->hex_x = e->cursor_x;
            e->hex_y = e->cursor_y;
            e->cursor_x = 1;
            e->cursor_y = 1;
            editor_statusmessage(e, STATUS_INFO, "View: ASM");
            break;
        case VIEW_HEX:
            editor_scroll_to_offset(e, e->line * e->octets_per_line);
            e->cursor_x = e->hex_x;
            e->cursor_y = e->hex_y;
            editor_statusmessage(e, STATUS_INFO, "View: HEX");
            break;
    }
}


void editor_setmode(struct editor* e, enum editor_mode mode) {
    e->mode = mode;
    switch (e->mode) {
        case MODE_NORMAL:        editor_statusmessage(e, STATUS_INFO, ""); break;
        case MODE_APPEND:        editor_statusmessage(e, STATUS_INFO, "Mode: APPEND"); break;
        case MODE_APPEND_ASCII:  editor_statusmessage(e, STATUS_INFO, "Mode: APPEND ASCII"); break;
        case MODE_REPLACE_ASCII: editor_statusmessage(e, STATUS_INFO, "Mode: REPLACE ASCII"); break;
        case MODE_INSERT:        editor_statusmessage(e, STATUS_INFO, "Mode: INSERT"); break;
        case MODE_INSERT_ASCII:  editor_statusmessage(e, STATUS_INFO, "Mode: INSERT ASCII"); break;
        case MODE_REPLACE:       editor_statusmessage(e, STATUS_INFO, "Mode: REPLACE"); break;
        case MODE_COMMAND: break;
        case MODE_SEARCH: break;
    }
}

int editor_statusmessage(struct editor* e, enum status_severity sev, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int x = vsnprintf(e->status_message, sizeof(e->status_message), fmt, ap);
    va_end(ap);
    e->status_severity = sev;
    return x;
}

void editor_render_header(struct editor* e, struct charbuf* b) {
    char banner[ 1024 + 1];
    int  banlen = 0;
    char model[] = "";
    char arch[10][8] = { "Unknown\0",
                         "  EM64T\0",
                         "AArch64\0",
                         " RISC-V\0",
                         "PowerPC\0",
                         " SuperH\0",
                         " M68000\0",
                         " MIPS64\0",
                         " PDP-11\0",
                         " nVidia\0", };
    int current_offset =  editor_offset_at_cursor(e);
    unsigned char active_byte = e->contents[current_offset];
    int arch_select = e->arch < 0 ? 0 : (e->arch > 9 ? 0 : e->arch);
    banlen = snprintf(banner, sizeof(banner),
           "\x1b[1;33m\x1b[33;44m▄\x1b[48;2;255;105;180m\x1b[1;37m BE \x1b[90;106m %12s [%03i][%s][%02x][%016x] Size: %012iB    ",
           arch[arch_select],
           e->seg_size, (e->view == VIEW_ASM ? "ASM" : "HEX"), active_byte,
           current_offset, e->content_length);
    charbuf_append(b, banner, banlen);

    unsigned int offset_at_cursor = editor_offset_at_cursor(e);
    unsigned char val = e->contents[offset_at_cursor];
    int percentage = (float)(offset_at_cursor + 1) / ((float)e->content_length) * 100;
    charbuf_appendf(b, "\x1b[1;33m\x1b[46m");
    int width = e->screen_cols - (16+32+64) - 38;
    char *format = "% 36d%% ";
    if (e->view == VIEW_HEX) { width = e->screen_cols - (16 + (24 * 4)) - 4; format = "% 36d%% "; }
    int file_position = snprintf(banner, sizeof(banner), format, percentage);
    charbuf_append(b, banner, file_position);
    charbuf_appendf(b, "\x1b[1;36m\x1b[0;36m");
    for (int i=0; i < width;i++) charbuf_appendf(b, " ");
    charbuf_appendf(b, "\r\n");
    charbuf_append(b, "\x1b[0m\x1b[K", 7);

}


void editor_render_help(struct editor* e) {
    (void) e;
    struct charbuf* b = charbuf_create();
    clear_screen();
    charbuf_append(b, "\x1b[?25l", 6); // hide cursor
    charbuf_appendf(b, "BE: InfoSec Hex Editor with Disassemblers, version %s\r\n\n", XT_VERSION);

    charbuf_appendf(b,
        "Available commands:\r\n"
        "\r\n"
        "CTRL+Q  : Quit immediately without saving.\r\n"
        "CTRL+S  : Save (in place).\r\n"
        "Arrows  : Also moves the cursor around.\r\n"
        "\r\n");

    charbuf_appendf(b,
        ":       : Command mode. Commands can be typed and executed.\r\n"
        "ESC     : Return to normal mode.\r\n"
        "End     : Move cursor to end of the offset line.\r\n"
        "Home    : Move cursor to the beginning of the offset line.\r\n"
        "\r\n"
    );

    charbuf_appendf(b, "Press any key to exit help.\r\n");
    charbuf_draw(b);
    read_key();
    clear_screen();
}

void editor_render_status(struct editor* e, struct charbuf* b) {
    charbuf_appendf(b, "\x1b[%d;0H", e->screen_rows);
    switch (e->status_severity) {
        case STATUS_INFO:    charbuf_append(b, "\x1b[0;30;47m", 10); break; // black on white
        case STATUS_WARNING: charbuf_append(b, "\x1b[0;30;43m", 10); break; // black on yellow
        case STATUS_ERROR:   charbuf_append(b, "\x1b[1;37;41m", 10); break; // white on red
    }

    int maxchars = strlen(e->status_message);
    if (e->screen_cols <= maxchars) maxchars = e->screen_cols;

    charbuf_append(b, e->status_message, maxchars);
    charbuf_append(b, "\x1b[0m\x1b[0K", 8);
}

void editor_process_command(struct editor* e, const char* cmd) {
    bool b = is_pos_num(cmd);
    if (b) {
        int offset = str2int(cmd, 0, e->content_length, e->content_length - 1);
        editor_scroll_to_offset(e, offset);
        editor_statusmessage(e, STATUS_INFO, "Positioned to offset 0x%09x (%d)", offset, offset);
        return;
    }

    if (cmd[0] == '0' && cmd[1] == 'x') {
        const char* ptr = &cmd[2];
        if (!is_hex(ptr)) {
            editor_statusmessage(e, STATUS_ERROR, "Error: %s is not valid base 16", ptr);
            return;
        }

        int offset = hex2int(ptr);
        editor_scroll_to_offset(e, offset);
        editor_statusmessage(e, STATUS_INFO, "Positioned to offset 0x%09x (%d)", offset, offset);
        return;
    }

    if (strncmp(cmd, "w", INPUT_BUF_SIZE) == 0) {
        editor_writefile(e);
        return;
    }

    if (strncmp(cmd, "q", INPUT_BUF_SIZE) == 0) {
        if (e->dirty) {
            editor_statusmessage(e, STATUS_ERROR, "No write since last change (add ! to override)", cmd);
            return;
        } else {
            exit(0);
        }
    }

    if (strncmp(cmd, "q!", INPUT_BUF_SIZE) == 0) {
        exit(0);
        return;
    }

    if (strncmp(cmd, "help", INPUT_BUF_SIZE) == 0) {
        editor_render_help(e);
        return;
    }

    if (strncmp(cmd, "set", 3) == 0) {
        char setcmd[INPUT_BUF_SIZE] = {0};
        int setval = 0;
        int items_read = sscanf(cmd, "set %[a-z]=%d", setcmd, &setval);

        if (items_read != 2) {
            editor_statusmessage(e, STATUS_ERROR, "set command format: `set cmd=num`");
            return;
        }

        if (strcmp(setcmd, "octets") == 0 || strcmp(setcmd, "o") == 0) {
            int octets = clampi(setval, 16, 64);
            clear_screen();
            int offset = editor_offset_at_cursor(e);
            e->octets_per_line = octets;
            editor_scroll_to_offset(e, offset);
            editor_statusmessage(e, STATUS_INFO, "Octets per line set to %d", octets);
            return;
        }

        if (strcmp(setcmd, "bitness") == 0 || strcmp(setcmd, "b") == 0) {
            int bitness = clampi(setval, 16, 64);
            clear_screen();
            e->seg_size = bitness;
            editor_statusmessage(e, STATUS_INFO, "Bitness is set to %d", bitness);
            return;
        }

        editor_statusmessage(e, STATUS_ERROR, "Unknown option: %s", setcmd);
        return;
    }
    editor_statusmessage(e, STATUS_ERROR, "Command not found: %s", cmd);
}


int editor_read_string(struct editor* e, char* dst, int len) {
    int c = read_key();
    if (c == KEY_ENTER || c == KEY_ESC) {
        editor_setmode(e, MODE_NORMAL);
        strncpy(dst, e->inputbuffer, len);
        e->inputbuffer_index = 0;
        memset(e->inputbuffer,  '\0', sizeof(e->inputbuffer));
        return c;
    }

    if (c == KEY_BACKSPACE && e->inputbuffer_index > 0) {
        e->inputbuffer_index--;
        e->inputbuffer[e->inputbuffer_index] = '\0';
        return c;
    }

    if ((size_t) e->inputbuffer_index >= sizeof(e->inputbuffer) - 1) {
        return c;
    }

    if (c == KEY_BACKSPACE && e->inputbuffer_index == 0) {
        editor_setmode(e, MODE_NORMAL);
        return c;
    }

    if (!isprint(c)) {
        return c;
    }

    e->inputbuffer[e->inputbuffer_index++] = c;
    return c;
}


void editor_free(struct editor* e) {
    struct editor* x = editor();
    free(x->filename);
    free(x->contents);
    free(x);
}

void editor_replace_byte(struct editor* e, char x) {
    switch (e->view) {
        case VIEW_ASM: editor_replace_byte_dasm(e, x); break;
        default:        editor_replace_byte_hex(e, x);
    }
}

void editor_insert_byte(struct editor* e, char x, bool after) {
    switch (e->view) {
        case VIEW_ASM: editor_insert_byte_dasm(e, x, after); break;
        default:        editor_insert_byte_hex(e, x, after);
    }
}

void editor_scroll(struct editor* e, int units) {
    switch (e->view) {
        case VIEW_ASM:  editor_scroll_dasm(e, units); break;
        default:        editor_scroll_hex(e, units);
    }
}

void editor_move_cursor(struct editor* e, int dir, int amount) {
    switch (e->view) {
        case VIEW_ASM: editor_move_cursor_dasm(e, dir, amount); break;
        default:        editor_move_cursor_hex(e, dir, amount);
    }
}

void editor_render_contents(struct editor* e, struct charbuf* b) {
    switch (e->view) {
        case VIEW_ASM: editor_render_dasm(e, b); break;
        case VIEW_HEX: editor_render_hex(e, b);
    }
}

int  _hexstr_idx = 0;
char _hexstr[2 + 1];

int  hexstr_idx_inc() { return _hexstr_idx++; }
int  hexstr_idx_set(int value) { return _hexstr_idx = value; }
int  hexstr_idx() { return _hexstr_idx; }
char hexstr_set(int pos, int value) { return _hexstr[pos] = value; };
char hexstr_get(int pos) { return _hexstr[pos]; };
char* hexstr() { return _hexstr; };

int editor_read_hex_input(struct editor* e, char* out) {

    int next = read_key();

    if (next == KEY_ESC) {
        editor_setmode(e, MODE_NORMAL);
        memset(hexstr(), '\0', 3);
        hexstr_idx_set(0);
        return -1;
    }

    if (!isprint(next)) return -1;
    if (!isxdigit(next)) return -1;

    hexstr_set(hexstr_idx_inc(),next);

    if (hexstr_idx() >= 2) {
        *out = hex2bin(hexstr());
        memset(hexstr(), '\0', 3);
        hexstr_idx_set(0);
        return 0;
    }

    return -1;
}

void editor_process_keypress(struct editor* e) {

    if (e->mode & (MODE_INSERT | MODE_APPEND)) {
        char out = 0;
        if (editor_read_hex_input(e, &out) != -1) {
            editor_insert_byte(e, out, e->mode & MODE_APPEND);
            editor_move_cursor(e, KEY_RIGHT, 1);
        }
        return;
    }

    if (e->mode & (MODE_INSERT_ASCII | MODE_APPEND_ASCII)) {
        char c = read_key();
        if (c == KEY_ESC) editor_setmode(e, MODE_NORMAL); return;
        editor_insert_byte(e, c, e->mode & MODE_APPEND_ASCII);
        editor_move_cursor(e, KEY_RIGHT, 1);
        return;
    }

    if (e->mode & MODE_REPLACE_ASCII) {
        char c = read_key();
        if (c == KEY_ESC) {
            editor_setmode(e, MODE_NORMAL);
            return;
        }

        if (e->content_length > 0) {
            editor_replace_byte(e, c);
        } else {
            editor_statusmessage(e, STATUS_ERROR, "File is empty, nothing to replace");
        }
        return;
    }

    if (e->mode & MODE_REPLACE) {
        char out = 0;
        if (e->content_length > 0) {
            if (editor_read_hex_input(e, &out) != -1) {
                editor_replace_byte(e, out);
            }
        } else {
            editor_statusmessage(e, STATUS_ERROR, "File is empty, nothing to replace");
        }
        return;
    }

    if (e->mode & MODE_COMMAND) {
        char cmd[INPUT_BUF_SIZE];
        int c = editor_read_string(e, cmd, INPUT_BUF_SIZE);
        if (c == KEY_ENTER && strlen(cmd) > 0) editor_process_command(e, cmd);
        return;
    }

    if (e->mode & MODE_SEARCH) {
        char search[INPUT_BUF_SIZE];
        int c = editor_read_string(e, search, INPUT_BUF_SIZE);
        if (c == KEY_ENTER && strlen(search) > 0) editor_process_search(e, search, SEARCH_FORWARD);
        return;
    }

    int c = read_key();
    if (c == -1) return;

    switch (c) {
        case KEY_ESC:    editor_setmode(e, MODE_NORMAL); return;
        case KEY_CTRL_Q: exit(0); return;
        case KEY_F3: exit(0); return;
        case KEY_CTRL_S: editor_writefile(e); return;
    }

    if (e->mode & MODE_NORMAL)
    {
        switch (c) {
        case KEY_UP:
        case KEY_DOWN:
        case KEY_RIGHT:
        case KEY_LEFT: editor_move_cursor(e, c, 1); return;
        case '1': e->cursor_x = 1; editor_statusmessage(e, STATUS_INFO, "Bitness: %i", e->seg_size = 8); return;
        case '2': e->cursor_x = 1; editor_statusmessage(e, STATUS_INFO, "Bitness: %i", e->seg_size = 16); return;
        case '3': e->cursor_x = 1; editor_statusmessage(e, STATUS_INFO, "Bitness: %i", e->seg_size = 32); return;
        case '4': e->cursor_x = 1; editor_statusmessage(e, STATUS_INFO, "Bitness: %i", e->seg_size = 64); return;
        case '5': e->cursor_x = 1; editor_statusmessage(e, STATUS_INFO, "Bitness: %i", e->seg_size = 128); return;
        case 'd': editor_setview(e, VIEW_ASM); return;
        case 'x': editor_setview(e, VIEW_HEX); return;
//      case 'a': editor_setmode(e, MODE_APPEND);       return;
//      case 'A': editor_setmode(e, MODE_APPEND_ASCII); return;
//      case 'i': editor_setmode(e, MODE_INSERT);       return;
//      case 'I': editor_setmode(e, MODE_INSERT_ASCII); return;
        case 'r': editor_setmode(e, MODE_REPLACE);      return;
        case 'R': editor_setmode(e, MODE_REPLACE_ASCII);return;
        case ':': editor_setmode(e, MODE_COMMAND);      return;
        case '/': editor_setmode(e, MODE_SEARCH);       return;
        case KEY_HOME: e->cursor_x = 1; return;
        case KEY_END:  editor_move_cursor(e, KEY_RIGHT, e->octets_per_line - e->cursor_x); return;
        case KEY_CTRL_U:
        case KEY_PGUP:   editor_scroll(e, -(e->screen_rows) + 2); return;
        case KEY_CTRL_D:
        case KEY_PGDOWN: editor_scroll(e, e->screen_rows - 2); return;
        }
    }
}

void editor_refresh_screen(struct editor* e) {
    struct charbuf* b = charbuf_create();
    charbuf_append(b, "\x1b[?25l", 6);
    charbuf_append(b, "\x1b[H", 3);
    if (e->mode & MODE_COMMAND) {
        charbuf_appendf(b, "\x1b[0m\x1b[?25h\x1b[%d;1H\x1b[2K:", e->screen_rows);
        charbuf_append(b, e->inputbuffer, e->inputbuffer_index);
    } else if (e->mode & MODE_SEARCH) {
        charbuf_appendf(b, "\x1b[0m\x1b[?25h\x1b[%d;1H\x1b[2K/", e->screen_rows);
        charbuf_append(b, e->inputbuffer, e->inputbuffer_index);
    } else {
        editor_render_header(e, b);
        editor_render_contents(e, b);
        editor_render_status(e, b);
    }
    charbuf_draw(b);
    charbuf_free(b);
}
