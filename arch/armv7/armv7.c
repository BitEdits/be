#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define INSN_SIZE 4

// Instruction decoding structure
typedef struct {
    uint32_t mask;
    uint32_t pattern;
    const char *mnemonic;
    void (*decode)(uint32_t insn, char *buf);
} Instruction;

// Common decode helpers
void decode_reg_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rd_pos, uint32_t rn_pos, uint32_t rm_pos) {
    uint32_t rd = (insn >> rd_pos) & 0xF;
    uint32_t rn = (insn >> rn_pos) & 0xF;
    uint32_t rm = (insn >> rm_pos) & 0xF;
    snprintf(buf, 64, "%s r%d, r%d, r%d", mnemonic, rd, rn, rm);
}

void decode_reg_imm_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rd_pos, uint32_t rn_pos, uint32_t imm_pos, uint32_t imm_width) {
    uint32_t rd = (insn >> rd_pos) & 0xF;
    uint32_t rn = (insn >> rn_pos) & 0xF;
    uint32_t imm = (insn >> imm_pos) & ((1 << imm_width) - 1);
    snprintf(buf, 64, "%s r%d, r%d, #%d", mnemonic, rd, rn, imm);
}

void decode_single_reg_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rd_pos, uint32_t rm_pos) {
    uint32_t rd = (insn >> rd_pos) & 0xF;
    uint32_t rm = (insn >> rm_pos) & 0xF;
    snprintf(buf, 64, "%s r%d, r%d", mnemonic, rd, rm);
}

void decode_shift_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rd_pos, uint32_t rm_pos, uint32_t imm_pos) {
    uint32_t rd = (insn >> rd_pos) & 0xF;
    uint32_t rm = (insn >> rm_pos) & 0xF;
    uint32_t imm = (insn >> imm_pos) & 0x1F;
    snprintf(buf, 64, "%s r%d, r%d, #%d", mnemonic, rd, rm, imm);
}

void decode_branch_op(uint32_t insn, char *buf, const char *mnemonic) {
    int32_t imm = (insn & 0x00FFFFFF) << 2;
    if (imm & 0x02000000) imm |= 0xFC000000; // Sign extend
    snprintf(buf, 64, "%s 0x%08x", mnemonic, imm);
}

void decode_load_store_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rd_pos, uint32_t rn_pos, uint32_t imm_pos) {
    uint32_t rd = (insn >> rd_pos) & 0xF;
    uint32_t rn = (insn >> rn_pos) & 0xF;
    uint32_t imm = (insn >> imm_pos) & 0xFFF;
    snprintf(buf, 64, "%s r%d, [r%d, #%d]", mnemonic, rd, rn, imm);
}

void decode_reg_list_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rn_pos) {
    uint32_t rn = (insn >> rn_pos) & 0xF;
    uint32_t rlist = insn & 0xFFFF;
    char reg_str[32] = "{";
    int len = 1, first = 1;
    for (int i = 0; i < 16 && len < 30; i++) {
        if (rlist & (1 << i)) {
            if (!first) {
                if (len + 2 < 30) { strcat(reg_str, ", "); len += 2; }
            }
            char temp[4];
            snprintf(temp, 4, "r%d", i);
            if (len + strlen(temp) < 30) { strcat(reg_str, temp); len += strlen(temp); }
            first = 0;
        }
    }
    if (len < 31 && !first) strcat(reg_str, "}");
    snprintf(buf, 64, "%s r%d!, %s", mnemonic, rn, reg_str);
}

void decode_default(uint32_t insn, char *buf) {
    snprintf(buf, 64, "UNDEFINED 0x%08x", insn);
}

// Baseline instruction decoders
void decode_adc(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "ADC", 12, 16, 0); }
void decode_add(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "ADD", 12, 16, 0); }
void decode_and(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "AND", 12, 16, 0); }
void decode_asr(uint32_t insn, char *buf) { decode_shift_op(insn, buf, "ASR", 12, 0, 7); }
void decode_bic(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "BIC", 12, 16, 0); }
void decode_cmn(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "CMN", 16, 0); }
void decode_cmp(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "CMP", 16, 0); }
void decode_eor(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "EOR", 12, 16, 0); }
void decode_lsl(uint32_t insn, char *buf) { decode_shift_op(insn, buf, "LSL", 12, 0, 7); }
void decode_lsr(uint32_t insn, char *buf) { decode_shift_op(insn, buf, "LSR", 12, 0, 7); }
void decode_mov(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "MOV", 12, 0); }
void decode_mul(uint32_t insn, char *buf) {
    uint32_t rd = (insn >> 16) & 0xF;
    uint32_t rm = (insn >> 0) & 0xF;
    uint32_t rs = (insn >> 8) & 0xF;
    snprintf(buf, 64, "MUL r%d, r%d, r%d", rd, rm, rs);
}
void decode_mvn(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "MVN", 12, 0); }
void decode_orr(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "ORR", 12, 16, 0); }
void decode_ror(uint32_t insn, char *buf) { decode_shift_op(insn, buf, "ROR", 12, 0, 7); }
void decode_rsb(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "RSB", 12, 16, 0); }
void decode_sbc(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SBC", 12, 16, 0); }
void decode_sub(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SUB", 12, 16, 0); }
void decode_teq(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "TEQ", 16, 0); }
void decode_tst(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "TST", 16, 0); }
void decode_b(uint32_t insn, char *buf) { decode_branch_op(insn, buf, "B"); }
void decode_bl(uint32_t insn, char *buf) { decode_branch_op(insn, buf, "BL"); }
void decode_bx(uint32_t insn, char *buf) { 
    uint32_t rm = (insn & 0xF);
    snprintf(buf, 64, "BX r%d", rm);
}
void decode_ldm(uint32_t insn, char *buf) { decode_reg_list_op(insn, buf, "LDM", 16); }
void decode_stm(uint32_t insn, char *buf) { decode_reg_list_op(insn, buf, "STM", 16); }
void decode_ldr(uint32_t insn, char *buf) { decode_load_store_op(insn, buf, "LDR", 12, 16, 0); }
void decode_str(uint32_t insn, char *buf) { decode_load_store_op(insn, buf, "STR", 12, 16, 0); }

// Full instruction decoders
void decode_cdp(uint32_t insn, char *buf) { 
    uint32_t cp = (insn >> 8) & 0xF;
    uint32_t op1 = (insn >> 20) & 0x7;
    uint32_t cd = (insn >> 12) & 0xF;
    uint32_t cn = (insn >> 16) & 0xF;
    uint32_t cm = (insn >> 0) & 0xF;
    uint32_t op2 = (insn >> 5) & 0x7;
    snprintf(buf, 64, "CDP p%d, #%d, cr%d, cr%d, cr%d, #%d", cp, op1, cd, cn, cm, op2);
}
void decode_ldc(uint32_t insn, char *buf) { 
    uint32_t cp = (insn >> 8) & 0xF;
    uint32_t cd = (insn >> 12) & 0xF;
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t imm = (insn >> 0) & 0xFFF;
    snprintf(buf, 64, "LDC p%d, cr%d, [r%d, #%d]", cp, cd, rn, imm);
}
void decode_mcr(uint32_t insn, char *buf) { 
    uint32_t cp = (insn >> 8) & 0xF;
    uint32_t op1 = (insn >> 21) & 0x7;
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t cn = (insn >> 16) & 0xF;
    uint32_t cm = (insn >> 0) & 0xF;
    uint32_t op2 = (insn >> 5) & 0x7;
    snprintf(buf, 64, "MCR p%d, #%d, r%d, cr%d, cr%d, #%d", cp, op1, rd, cn, cm, op2);
}
void decode_mrc(uint32_t insn, char *buf) { 
    uint32_t cp = (insn >> 8) & 0xF;
    uint32_t op1 = (insn >> 21) & 0x7;
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t cn = (insn >> 16) & 0xF;
    uint32_t cm = (insn >> 0) & 0xF;
    uint32_t op2 = (insn >> 5) & 0x7;
    snprintf(buf, 64, "MRC p%d, #%d, r%d, cr%d, cr%d, #%d", cp, op1, rd, cn, cm, op2);
}
void decode_pld(uint32_t insn, char *buf) { 
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t imm = (insn >> 0) & 0xFFF;
    snprintf(buf, 64, "PLD [r%d, #%d]", rn, imm);
}
void decode_stc(uint32_t insn, char *buf) { 
    uint32_t cp = (insn >> 8) & 0xF;
    uint32_t cd = (insn >> 12) & 0xF;
    uint32_t rn = (insn >> 16) & 0xF;
    uint32_t imm = (insn >> 0) & 0xFFF;
    snprintf(buf, 64, "STC p%d, cr%d, [r%d, #%d]", cp, cd, rn, imm);
}
void decode_swi(uint32_t insn, char *buf) { 
    uint32_t imm = (insn >> 0) & 0xFFFFFF;
    snprintf(buf, 64, "SWI #%d", imm);
}
void decode_swp(uint32_t insn, char *buf) { 
    uint32_t rd = (insn >> 12) & 0xF;
    uint32_t rm = (insn >> 0) & 0xF;
    uint32_t rn = (insn >> 16) & 0xF;
    snprintf(buf, 64, "SWP r%d, r%d, [r%d]", rd, rm, rn);
}
void decode_udf(uint32_t insn, char *buf) { 
    uint32_t imm = (insn >> 0) & 0xFFFFFF;
    snprintf(buf, 64, "UDF #%d", imm);
}
void decode_umull(uint32_t insn, char *buf) { 
    uint32_t rdlo = (insn >> 12) & 0xF;
    uint32_t rdhi = (insn >> 16) & 0xF;
    uint32_t rm = (insn >> 0) & 0xF;
    uint32_t rs = (insn >> 8) & 0xF;
    snprintf(buf, 64, "UMULL r%d, r%d, r%d, r%d", rdlo, rdhi, rm, rs);
}

// Instruction table with corrected patterns
Instruction instructions[] = {
    // Data Processing (specific patterns)
    {0x0FE00000, 0x00000000, "AND", decode_and},
    {0x0FE00000, 0x02000000, "EOR", decode_eor},
    {0x0FE00000, 0x04000000, "SUB", decode_sub},
    {0x0FE00000, 0x06000000, "RSB", decode_rsb},
    {0x0FE00000, 0x08000000, "ADD", decode_add},
    {0x0FE00000, 0x0A000000, "ADC", decode_adc},
    {0x0FE00000, 0x0E000000, "SBC", decode_sbc},
    {0x0FE00010, 0x0C000000, "ORR", decode_orr},
    {0x0FE00000, 0x0EC00000, "BIC", decode_bic},
    {0x0FA000F0, 0x06A00010, "ASR", decode_asr},
    {0x0FA000F0, 0x06000000, "LSL", decode_lsl},
    {0x0FA000F0, 0x06200000, "LSR", decode_lsr},
    {0x0FA000F0, 0x06600000, "ROR", decode_ror},
    {0x0DE00000, 0x01A00000, "MOV", decode_mov},
    {0x0DE00000, 0x01E00000, "MVN", decode_mvn},
    {0x0FF000F0, 0x05000010, "CMP", decode_cmp},
    {0x0FF000F0, 0x07000010, "CMN", decode_cmn},
    {0x0FF000F0, 0x05000000, "TST", decode_tst},
    {0x0FF000F0, 0x07000010, "TEQ", decode_teq},
    {0x0FE000F0, 0x09000000, "MUL", decode_mul},
    // Load/Store
    {0x0C500000, 0x04000000, "STR", decode_str},
    {0x0C500000, 0x04100000, "LDR", decode_ldr}, // Adjusted pattern for load
    // Multiple
    {0x0E900000, 0x08900000, "LDM", decode_ldm},
    {0x0E900000, 0x08000000, "STM", decode_stm},
    // Branch
    {0x0FFFFFF0, 0x012FFF10, "BX", decode_bx},
    {0xF0000000, 0x0A000000, "B", decode_b},
    {0xF0000000, 0x0B000000, "BL", decode_bl},
    // Full Instructions
    {0x0FE000F0, 0x08400000, "UMULL", decode_umull},
    {0x0FF00FF0, 0x01000900, "SWP", decode_swp},
    {0xFE000000, 0xEE000000, "MCR", decode_mcr}, // Adjusted pattern for unconditional
    {0xFE000000, 0xEF000000, "MRC", decode_mrc}, // Adjusted pattern for unconditional
    {0xFE000000, 0xFE000000, "CDP", decode_cdp},
    {0xFE000000, 0xFC000000, "LDC", decode_ldc},
    {0xFE000000, 0xF5000000, "PLD", decode_pld},
    {0xFE000000, 0xF4000000, "STC", decode_stc},
    {0xF0000000, 0xFF000000, "SWI", decode_swi},
    {0xF0000000, 0xF7000000, "UDF", decode_udf},
    {0x00000000, 0x00000000, "UNDEFINED", decode_default}
};

void disassemble(uint32_t insn, char *buf) {
    uint32_t cond = (insn >> 28) & 0xF;
    if (cond > 0xF) {
        snprintf(buf, 64, "INVALID 0x%08x", insn);
        return;
    }
    for (int i = 0; instructions[i].mask != 0; i++) {
        if ((insn & instructions[i].mask) == (instructions[i].pattern | (cond << 28))) {
            instructions[i].decode(insn, buf);
            return;
        }
    }
    decode_default(insn, buf);
}

int main() {
    uint32_t code[] = {
        0xE0801002, // ADD r1, r0, #2
        0xE5913000, // LDR r3, [r1]
        0xEAFFFFFE, // B 0xFFFFFFFC
        0xEE000000  // MCR p0, #0, r0, cr0, cr0, #0 (unconditional)
    };
    char output[64];
    uint32_t addr = 0x00000000;

    for (int i = 0; i < sizeof(code) / INSN_SIZE; i++) {
        disassemble(code[i], output);
        printf("%08x: %s (0x%08x)\n", addr, output, code[i]);
        addr += INSN_SIZE;
    }

    return 0;
}
