#include <stdio.h>
#include <stdint.h>

uint32_t extract_bits(uint32_t word, int start, int length) {
    return (word >> start) & ((1U << length) - 1);
}

int32_t sign_extend(uint32_t value, int bits) {
    int32_t mask = 1 << (bits - 1);
    return (value ^ mask) - mask;
}

void decode_rv32i(uint32_t instruction) {
    uint32_t opcode = extract_bits(instruction, 0, 7);
    uint32_t rd = extract_bits(instruction, 7, 5);
    uint32_t funct3 = extract_bits(instruction, 12, 3);
    uint32_t rs1 = extract_bits(instruction, 15, 5);
    uint32_t rs2 = extract_bits(instruction, 20, 5);
    uint32_t funct7 = extract_bits(instruction, 25, 7);
    int32_t imm_i = sign_extend(extract_bits(instruction, 20, 12), 12);
    int32_t imm_s = sign_extend((extract_bits(instruction, 25, 7) << 5) | extract_bits(instruction, 7, 5), 12);
    int32_t imm_b = sign_extend((extract_bits(instruction, 31, 1) << 12) |
                                 (extract_bits(instruction, 7, 1) << 11) |
                                 (extract_bits(instruction, 25, 6) << 5) |
                                 (extract_bits(instruction, 8, 4)), 13);
    int32_t imm_u = instruction & 0xFFFFF000;
    int32_t imm_j = sign_extend((extract_bits(instruction, 31, 1) << 20) |
                                 (extract_bits(instruction, 12, 8) << 12) |
                                 (extract_bits(instruction, 20, 1) << 11) |
                                 (extract_bits(instruction, 21, 10) << 1), 21);

    switch (opcode) {
        case 0x33: // R-type
            switch (funct3) {
                case 0x0: printf(funct7 == 0x20 ? "sub x%d, x%d, x%d\n" : "add x%d, x%d, x%d\n", rd, rs1, rs2); break;
                case 0x7: printf("and x%d, x%d, x%d\n", rd, rs1, rs2); break;
                case 0x6: printf("or x%d, x%d, x%d\n", rd, rs1, rs2); break;
                case 0x4: printf("xor x%d, x%d, x%d\n", rd, rs1, rs2); break;
                case 0x1: printf("sll x%d, x%d, x%d\n", rd, rs1, rs2); break;
                case 0x5: printf(funct7 == 0x20 ? "sra x%d, x%d, x%d\n" : "srl x%d, x%d, x%d\n", rd, rs1, rs2); break;
            }
            break;
        case 0x13: // I-type
            switch (funct3) {
                case 0x0: printf("addi x%d, x%d, %d\n", rd, rs1, imm_i); break;
                case 0x7: printf("andi x%d, x%d, %d\n", rd, rs1, imm_i); break;
                case 0x6: printf("ori x%d, x%d, %d\n", rd, rs1, imm_i); break;
                case 0x1: printf("slli x%d, x%d, %d\n", rd, rs1, imm_i & 0x1F); break;
                case 0x5: printf((funct7 == 0x20 ? "srai" : "srli"), rd, rs1, imm_i & 0x1F); break;
            }
            break;
        case 0x03: // Load
            switch (funct3) {
                case 0x2: printf("lw x%d, %d(x%d)\n", rd, imm_i, rs1); break;
            }
            break;
        case 0x23: // S-type
            switch (funct3) {
                case 0x2: printf("sw x%d, %d(x%d)\n", rs2, imm_s, rs1); break;
            }
            break;
        case 0x63: // B-type
            switch (funct3) {
                case 0x0: printf("beq x%d, x%d, %d\n", rs1, rs2, imm_b); break;
                case 0x1: printf("bne x%d, x%d, %d\n", rs1, rs2, imm_b); break;
            }
            break;
        case 0x37: // U-type
            printf("lui x%d, %d\n", rd, imm_u); break;
        case 0x6F: // J-type
            printf("jal x%d, %d\n", rd, imm_j); break;
        case 0x67: // JALR
            printf("jalr x%d, %d(x%d)\n", rd, imm_i, rs1); break;
        default:
            printf("Unknown instruction: 0x%08X\n", instruction);
            break;
    }
}

int main() {
    uint32_t instruction;
    printf("RISC-V (RV32I) Disassembler (c) 2025 Namdak Tonpa.\n");
    printf("Enter RV32I instructions in hexadecimal (one per line, Ctrl+D to end):\n");
    while (scanf("%x", &instruction) == 1) {
        decode_rv32i(instruction);
    }

    return 0;
}

