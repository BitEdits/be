// BE: INFOSEC BINARY HEX EDITOR WITH DASM
// Synrc Research (c) 2022-2023
// 5HT DHARMA License

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>

#include "editor.h"
#include "term/terminal.h"
#include "dasm/dasm.h"

volatile sig_atomic_t resizeflag;

static void editor_exit() {
    struct editor* e = editor();
    editor_free(e);
    clear_screen();
    disable_raw_mode();
    term_state_restore();
}

static void print_help(const char* explanation) {
    fprintf(stderr,
        "%s"\
        "Usage: be [-vhdbao] <filename>\n"\
        "\n"
        "Options:\n"
        "    -v           Get version information\n"
        "    -h           Print usage info and exits\n"
        "    -d           Launch ASM view by default\n"
        "    -b bitness   CPU Bitness\n"
        "    -a arch      1:EM64T, 2:ARM, 3:RISC-V, 4:PPC, 5:SH-4, 6:M68K, 7:MIPS, 8:PDP-11, 9:nVidia\n"
        "    -o octets    Octets per screen for HEX view\n"
        "\n"
        "Report bugs to <be@5ht.co>\n", explanation);
}

void print_version() {
    printf("BE version %s codename %s released %s\n", XT_VERSION, XT_RELEASE_CODENAME, XT_RELEASE_DATE);
}

static void handle_term_resize(int sig) {
    (void)(sig);
    resizeflag = 1;
}

static void resize_term() {
    struct editor *e = editor();
    clear_screen();
    get_window_size(&(e->screen_rows), &(e->screen_cols));
}

int main(int argc, char* argv[]) {
    char* file = NULL;
    int ch = 0, bitness = 64, opl = 24, view = 0, arch = ARCH_INTEL;
    while ((ch = getopt(argc, argv, "vhdb:o:a:")) != -1) {
        switch (ch) {
            case 'v': print_version(); return 0;
            case 'h': print_help(""); exit(0); break;
            case 'o': opl = str2int(optarg, 16, 64, 16); break;
            case 'b': bitness = str2int(optarg, 16, 128, 16); break;
            case 'a': arch = (enum dasm_arch)str2int(optarg, 0, 10, 1); break;
            case 'd': view = VIEW_ASM; break;
            default: print_help(""); exit(1); break;
        }
    }

    if (optind >= argc) {
        print_help("Error: filename is expected.\n");
        exit(1);
    }

    file = argv[optind];

    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = handle_term_resize;
    sigaction(SIGWINCH, &act, NULL);
    resizeflag = 0;

    editor_init();
    struct editor* e = editor();

    editor_openfile(e, file);
    enable_raw_mode();
    term_state_save();
    atexit(editor_exit);
    clear_screen();
    e->octets_per_line = opl;
    e->seg_size = bitness;
    e->arch = arch;
    editor_setview(e, view ? VIEW_ASM : VIEW_HEX);
    nasm_init(e);

    while (true) {
        editor_refresh_screen(e);
        editor_process_keypress(e);
        if (resizeflag == 1) {
            resize_term();
            resizeflag = 0;
        }
    }

    editor_free(e);
    return 0;
}
