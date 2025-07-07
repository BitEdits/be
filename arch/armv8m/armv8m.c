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

// Common decode helpers to reduce duplication
void decode_reg_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rd_pos, uint32_t rn_pos, uint32_t rm_pos) {
    uint32_t rd = (insn >> rd_pos) & 0x7;
    uint32_t rn = (insn >> rn_pos) & 0x7;
    uint32_t rm = (insn >> rm_pos) & 0x7;
    snprintf(buf, 32, "%s r%d, r%d, r%d", mnemonic, rd, rn, rm);
}

void decode_reg_imm_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rd_pos, uint32_t rn_pos, uint32_t imm_pos, uint32_t imm_width) {
    uint32_t rd = (insn >> rd_pos) & 0x7;
    uint32_t rn = (insn >> rn_pos) & 0x7;
    uint32_t imm = (insn >> imm_pos) & ((1 << imm_width) - 1);
    snprintf(buf, 32, "%s r%d, r%d, #%d", mnemonic, rd, rn, imm);
}

void decode_single_reg_op(uint32_t insn, char *buf, const char *mnemonic, uint32_t rd_pos, uint32_t rm_pos) {
    uint32_t rd = (insn >> rd_pos) & 0x7;
    uint32_t rm = (insn >> rm_pos) & 0x7;
    snprintf(buf, 32, "%s r%d, r%d", mnemonic, rd, rm);
}

void decode_default(uint32_t insn, char *buf) {
    snprintf(buf, 32, "UNDEFINED 0x%08x", insn);
}

// Baseline instruction decoders
void decode_pkhbt(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "PKHBT", 8, 5, 0, 5); }
void decode_pkhtb(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "PKHTB", 8, 5, 0, 5); }
void decode_qadd(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QADD", 8, 5, 0); }
void decode_qadd16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QADD16", 8, 5, 0); }
void decode_qadd8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QADD8", 8, 5, 0); }
void decode_qasx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QASX", 8, 5, 0); }
void decode_qdadd(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QDADD", 8, 5, 0); }
void decode_qdsub(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QDSUB", 8, 5, 0); }
void decode_sadd16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SADD16", 8, 5, 0); }
void decode_sadd8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SADD8", 8, 5, 0); }
void decode_sasx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SASX", 8, 5, 0); }
void decode_sel(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SEL", 8, 5, 0); }
void decode_shadd16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SHADD16", 8, 5, 0); }
void decode_shadd8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SHADD8", 8, 5, 0); }
void decode_shasx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SHASX", 8, 5, 0); }
void decode_shsax(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SHSAX", 8, 5, 0); }
void decode_shsub16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SHSUB16", 8, 5, 0); }
void decode_shsub8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SHSUB8", 8, 5, 0); }
void decode_smlal(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLAL", 12, 8, 0); }
void decode_smlalbb(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLALBB", 12, 8, 0); }
void decode_smlalbt(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLALBT", 12, 8, 0); }
void decode_smlalt(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLALT", 12, 8, 0); }
void decode_smlaltb(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLALTB", 12, 8, 0); }
void decode_smlawb(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLAWB", 8, 5, 0); }
void decode_smlawt(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLAWT", 8, 5, 0); }
void decode_smlsd(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLSD", 8, 5, 0); }
void decode_smlsdx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLSDX", 8, 5, 0); }
void decode_smlsld(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLSLD", 8, 5, 0); }
void decode_smlsldx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMLSLDX", 8, 5, 0); }
void decode_smmla(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMMLA", 8, 5, 0); }
void decode_smmlar(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMMLAR", 8, 5, 0); }
void decode_smmul(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMMUL", 8, 5, 0); }
void decode_smmulr(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMMULR", 8, 5, 0); }
void decode_smuad(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMUAD", 8, 5, 0); }
void decode_smuadx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMUADX", 8, 5, 0); }
void decode_smulbb(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMULBB", 8, 5, 0); }
void decode_smulbt(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMULBT", 8, 5, 0); }
void decode_smultb(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMULTB", 8, 5, 0); }
void decode_smultt(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMULTT", 8, 5, 0); }
void decode_smulwb(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMULWB", 8, 5, 0); }
void decode_smulwt(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SMULWT", 8, 5, 0); }
void decode_pkabs(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "PKABS", 8, 0); }
void decode_pkadd(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "PKADD", 8, 5, 0); }
void decode_pksub(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "PKSUB", 8, 5, 0); }
void decode_qsub(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QSUB", 8, 5, 0); }
void decode_qsub16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QSUB16", 8, 5, 0); }
void decode_qsub8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "QSUB8", 8, 5, 0); }
void decode_sbc(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SBC", 8, 5, 0); }
void decode_sbfx(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "SBFX", 8, 5, 0, 5); }
void decode_sdiv(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SDIV", 8, 5, 0); }
void decode_ssat(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "SSAT", 8, 0, 5, 5); }
void decode_ssat16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "SSAT16", 8, 0, 5, 5); }
void decode_ssax(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SSAX", 8, 5, 0); }
void decode_ssub16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SSUB16", 8, 5, 0); }
void decode_ssub8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "SSUB8", 8, 5, 0); }
void decode_uadd16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UADD16", 8, 5, 0); }
void decode_uadd8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UADD8", 8, 5, 0); }
void decode_uasx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UASX", 8, 5, 0); }
void decode_ubfx(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "UBFX", 8, 5, 0, 5); }
void decode_udiv(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UDIV", 8, 5, 0); }
void decode_uhadd16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UHADD16", 8, 5, 0); }
void decode_uhadd8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UHADD8", 8, 5, 0); }
void decode_uhasx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UHASX", 8, 5, 0); }
void decode_uhsax(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UHSAX", 8, 5, 0); }
void decode_uhsub16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UHSUB16", 8, 5, 0); }
void decode_uhsub8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UHSUB8", 8, 5, 0); }
void decode_umaal(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UMAAL", 12, 8, 0); }
void decode_umlal(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UMLAL", 12, 8, 0); }
void decode_umlsl(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UMLSL", 12, 8, 0); }
void decode_umull(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UMULL", 12, 8, 0); }
void decode_uqadd16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UQADD16", 8, 5, 0); }
void decode_uqadd8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UQADD8", 8, 5, 0); }
void decode_uqasx(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UQASX", 8, 5, 0); }
void decode_uqsub16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UQSUB16", 8, 5, 0); }
void decode_uqsub8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UQSUB8", 8, 5, 0); }
void decode_usad8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "USAD8", 8, 5, 0); }
void decode_usada8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "USADA8", 8, 5, 0); }
void decode_usat(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "USAT", 8, 0, 5, 5); }
void decode_usat16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "USAT16", 8, 0, 5, 5); }
void decode_usax(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "USAX", 8, 5, 0); }
void decode_usub16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "USUB16", 8, 5, 0); }
void decode_usub8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "USUB8", 8, 5, 0); }
void decode_uxtab(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UXTAB", 8, 5, 0); }
void decode_uxtab16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UXTAB16", 8, 5, 0); }
void decode_uxtah(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "UXTAH", 8, 5, 0); }

// Full instruction decoders (partial implementation)
void decode_vaba_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VABA.s16", 12, 8, 0); }
void decode_vabd_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VABD.s16", 12, 8, 0); }
void decode_vabs_s16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VABS.s16", 12, 0); }
void decode_vacge_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VACGE.f32", 12, 8, 0); }
void decode_vacgt_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VACGT.f32", 12, 8, 0); }
void decode_vacle_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VACLE.f32", 12, 8, 0); }
void decode_vaclt_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VACLT.f32", 12, 8, 0); }
void decode_vadd_i16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VADD.i16", 12, 8, 0); }
void decode_vaddl_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VADDL.s16", 12, 8, 0); }
void decode_vaddw_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VADDW.s16", 12, 8, 0); }
void decode_vand(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VAND", 12, 8, 0); }
void decode_vbic(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VBIC", 12, 8, 0); }
void decode_vbif(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VBIF", 12, 8, 0); }
void decode_vbit(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VBIT", 12, 8, 0); }
void decode_vbsl(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VBSL", 12, 8, 0); }
void decode_vceq_i16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VCEQ.i16", 12, 8, 0); }
void decode_vcge_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VCGE.s16", 12, 8, 0); }
void decode_vcgt_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VCGT.s16", 12, 8, 0); }
void decode_vcle_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VCLE.s16", 12, 8, 0); }
void decode_vclt_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VCLT.s16", 12, 8, 0); }
void decode_vclz_i16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VCLZ.i16", 12, 0); }
void decode_vcmp_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VCMP.f32", 12, 8, 0); }
void decode_vcmpe_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VCMPE.f32", 12, 8, 0); }
void decode_vcnt_8(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VCNT.8", 12, 0); }
void decode_vdiv_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VDIV.f32", 12, 8, 0); }
void decode_vdup_16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VDUP.16", 12, 0); }
void decode_veor(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VEOR", 12, 8, 0); }
void decode_vext_8(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "VEXT.8", 12, 8, 0, 5); }
void decode_vhadd_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VHADD.s16", 12, 8, 0); }
void decode_vhsub_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VHSUB.s16", 12, 8, 0); }
void decode_vld1_16(uint32_t insn, char *buf) { snprintf(buf, 32, "VLD1.16 {D}, [r%d]", (insn >> 5) & 0x7); }
void decode_vld2_16(uint32_t insn, char *buf) { snprintf(buf, 32, "VLD2.16 {D, D}, [r%d]", (insn >> 5) & 0x7); }
void decode_vld3_16(uint32_t insn, char *buf) { snprintf(buf, 32, "VLD3.16 {D, D, D}, [r%d]", (insn >> 5) & 0x7); }
void decode_vld4_16(uint32_t insn, char *buf) { snprintf(buf, 32, "VLD4.16 {D, D, D, D}, [r%d]", (insn >> 5) & 0x7); }
void decode_vldm(uint32_t insn, char *buf) { snprintf(buf, 32, "VLDM s0-s31, [r%d]!", (insn >> 5) & 0x7); }
void decode_vlla(uint32_t insn, char *buf) { snprintf(buf, 32, "VLLA Qd, [r%d]", (insn >> 5) & 0x7); }
void decode_vmax_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMAX.s16", 12, 8, 0); }
void decode_vmaxa_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMAXA.s16", 12, 8, 0); }
void decode_vmin_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMIN.s16", 12, 8, 0); }
void decode_vmina_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMINA.s16", 12, 8, 0); }
void decode_vmla_i16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMLA.i16", 12, 8, 0); }
void decode_vmlal_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMLAL.s16", 12, 8, 0); }
void decode_vmls_i16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMLS.i16", 12, 8, 0); }
void decode_vmlsl_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMLSL.s16", 12, 8, 0); }
void decode_vmov_i16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "VMOV.i16", 12, 0, 5, 5); }
void decode_vmovl_s16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VMOVL.s16", 12, 0); }
void decode_vmovn_i16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VMOVN.i16", 12, 0); }
void decode_vmrs(uint32_t insn, char *buf) { snprintf(buf, 32, "VMRS r0, fpscr"); }
void decode_vmsr(uint32_t insn, char *buf) { snprintf(buf, 32, "VMSR fpscr, r0"); }
void decode_vmul_i16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMUL.i16", 12, 8, 0); }
void decode_vmull_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VMULL.s16", 12, 8, 0); }
void decode_vmvn(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VMVN", 12, 0); }
void decode_vneg_s16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VNEG.s16", 12, 0); }
void decode_vnmla_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VNMLA.f32", 12, 8, 0); }
void decode_vnmls_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VNMLS.f32", 12, 8, 0); }
void decode_vnmlal_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VNMLAL.s16", 12, 8, 0); }
void decode_vnmlsl_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VNMLSL.s16", 12, 8, 0); }
void decode_vnmul_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VNMUL.f32", 12, 8, 0); }
void decode_vpadal_s16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VPADAL.s16", 12, 0); }
void decode_vpadd_i16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VPADD.i16", 12, 8, 0); }
void decode_vpaddl_s16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VPADDL.s16", 12, 0); }
void decode_vpmin_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VPMIN.s16", 12, 8, 0); }
void decode_vpmax_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VPMAX.s16", 12, 8, 0); }
void decode_vqadd_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VQADD.s16", 12, 8, 0); }
void decode_vqsub_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VQSUB.s16", 12, 8, 0); }
void decode_vraddhn_i16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VRADDHN.i16", 12, 8, 0); }
void decode_vrecpe_u32(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VRECPE.u32", 12, 0); }
void decode_vrecps_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VRECPS.f32", 12, 8, 0); }
void decode_vrsqrte_u32(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VRSQRTE.u32", 12, 0); }
void decode_vrsqrts_f32(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VRSQRTS.f32", 12, 8, 0); }
void decode_vshl_i16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "VSHL.i16", 12, 8, 0, 5); }
void decode_vshll_s16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "VSHLL.s16", 12, 8, 0, 5); }
void decode_vshr_s16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "VSHR.s16", 12, 8, 0, 5); }
void decode_vrev16_8(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VREV16.8", 12, 0); }
void decode_vrev32_8(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VREV32.8", 12, 0); }
void decode_vrev64_8(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VREV64.8", 12, 0); }
void decode_vsri_16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "VSRI.16", 12, 8, 0, 5); }
void decode_vsli_16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "VSLI.16", 12, 8, 0, 5); }
void decode_vsra_s16(uint32_t insn, char *buf) { decode_reg_imm_op(insn, buf, "VSRA.s16", 12, 8, 0, 5); }
void decode_vsub_i16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VSUB.i16", 12, 8, 0); }
void decode_vsubl_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VSUBL.s16", 12, 8, 0); }
void decode_vsubw_s16(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VSUBW.s16", 12, 8, 0); }
void decode_vswp(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VSWP", 12, 8, 0); }
void decode_vtbl_8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VTBL.8", 12, 8, 0); }
void decode_vtbx_8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VTBX.8", 12, 8, 0); }
void decode_vtrn_16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VTRN.16", 12, 0); }
void decode_vtst_8(uint32_t insn, char *buf) { decode_reg_op(insn, buf, "VTST.8", 12, 8, 0); }
void decode_vuzp_16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VUZP.16", 12, 0); }
void decode_vzip_16(uint32_t insn, char *buf) { decode_single_reg_op(insn, buf, "VZIP.16", 12, 0); }

// Instruction table (partial patterns, to be completed with exact encodings)
Instruction instructions[] = {
    {0xFFC0, 0x4400, "PKHBT", decode_pkhbt},
    {0xFFC0, 0x4401, "PKHTB", decode_pkhtb},
    {0xFFC0, 0x4402, "QADD", decode_qadd},
    {0xFFC0, 0x4403, "QADD16", decode_qadd16},
    {0xFFC0, 0x4404, "QADD8", decode_qadd8},
    {0xFFC0, 0x4405, "QASX", decode_qasx},
    {0xFFC0, 0x4406, "QDADD", decode_qdadd},
    {0xFFC0, 0x4407, "QDSUB", decode_qdsub},
    {0xFFC0, 0x4408, "SADD16", decode_sadd16},
    {0xFFC0, 0x4409, "SADD8", decode_sadd8},
    {0xFFC0, 0x440A, "SASX", decode_sasx},
    {0xFFC0, 0x440B, "SEL", decode_sel},
    {0xFFC0, 0x440C, "SHADD16", decode_shadd16},
    {0xFFC0, 0x440D, "SHADD8", decode_shadd8},
    {0xFFC0, 0x440E, "SHASX", decode_shasx},
    {0xFFC0, 0x440F, "SHSAX", decode_shsax},
    {0xFFC0, 0x4410, "SHSUB16", decode_shsub16},
    {0xFFC0, 0x4411, "SHSUB8", decode_shsub8},
    {0xFFE0, 0x4420, "SMLAL", decode_smlal},
    {0xFFE0, 0x4421, "SMLALBB", decode_smlalbb},
    {0xFFE0, 0x4422, "SMLALBT", decode_smlalbt},
    {0xFFE0, 0x4423, "SMLALT", decode_smlalt},
    {0xFFE0, 0x4424, "SMLALTB", decode_smlaltb},
    {0xFFC0, 0x4425, "SMLAWB", decode_smlawb},
    {0xFFC0, 0x4426, "SMLAWT", decode_smlawt},
    {0xFFC0, 0x4427, "SMLSD", decode_smlsd},
    {0xFFC0, 0x4428, "SMLSDX", decode_smlsdx},
    {0xFFC0, 0x4429, "SMLSLD", decode_smlsld},
    {0xFFC0, 0x442A, "SMLSLDX", decode_smlsldx},
    {0xFFC0, 0x442B, "SMMLA", decode_smmla},
    {0xFFC0, 0x442C, "SMMLAR", decode_smmlar},
    {0xFFC0, 0x442D, "SMMUL", decode_smmul},
    {0xFFC0, 0x442E, "SMMULR", decode_smmulr},
    {0xFFC0, 0x442F, "SMUAD", decode_smuad},
    {0xFFC0, 0x4430, "SMUADX", decode_smuadx},
    {0xFFC0, 0x4431, "SMULBB", decode_smulbb},
    {0xFFC0, 0x4432, "SMULBT", decode_smulbt},
    {0xFFC0, 0x4433, "SMULTB", decode_smultb},
    {0xFFC0, 0x4434, "SMULTT", decode_smultt},
    {0xFFC0, 0x4435, "SMULWB", decode_smulwb},
    {0xFFC0, 0x4436, "SMULWT", decode_smulwt},
    {0xFFC0, 0x4437, "PKABS", decode_pkabs},
    {0xFFC0, 0x4438, "PKADD", decode_pkadd},
    {0xFFC0, 0x4439, "PKSUB", decode_pksub},
    {0xFFC0, 0x443A, "QSUB", decode_qsub},
    {0xFFC0, 0x443B, "QSUB16", decode_qsub16},
    {0xFFC0, 0x443C, "QSUB8", decode_qsub8},
    {0xFFC0, 0x443D, "SBC", decode_sbc},
    {0xFFC0, 0x443E, "SBFX", decode_sbfx},
    {0xFFC0, 0x443F, "SDIV", decode_sdiv},
    {0xFFC0, 0x4440, "SSAT", decode_ssat},
    {0xFFC0, 0x4441, "SSAT16", decode_ssat16},
    {0xFFC0, 0x4442, "SSAX", decode_ssax},
    {0xFFC0, 0x4443, "SSUB16", decode_ssub16},
    {0xFFC0, 0x4444, "SSUB8", decode_ssub8},
    {0xFFC0, 0x4445, "UADD16", decode_uadd16},
    {0xFFC0, 0x4446, "UADD8", decode_uadd8},
    {0xFFC0, 0x4447, "UASX", decode_uasx},
    {0xFFC0, 0x4448, "UBFX", decode_ubfx},
    {0xFFC0, 0x4449, "UDIV", decode_udiv},
    {0xFFC0, 0x444A, "UHADD16", decode_uhadd16},
    {0xFFC0, 0x444B, "UHADD8", decode_uhadd8},
    {0xFFC0, 0x444C, "UHASX", decode_uhasx},
    {0xFFC0, 0x444D, "UHSAX", decode_uhsax},
    {0xFFC0, 0x444E, "UHSUB16", decode_uhsub16},
    {0xFFC0, 0x444F, "UHSUB8", decode_uhsub8},
    {0xFFE0, 0x4450, "UMAAL", decode_umaal},
    {0xFFE0, 0x4451, "UMLAL", decode_umlal},
    {0xFFE0, 0x4452, "UMLSL", decode_umlsl},
    {0xFFE0, 0x4453, "UMULL", decode_umull},
    {0xFFC0, 0x4454, "UQADD16", decode_uqadd16},
    {0xFFC0, 0x4455, "UQADD8", decode_uqadd8},
    {0xFFC0, 0x4456, "UQASX", decode_uqasx},
    {0xFFC0, 0x4457, "UQSUB16", decode_uqsub16},
    {0xFFC0, 0x4458, "UQSUB8", decode_uqsub8},
    {0xFFC0, 0x4459, "USAD8", decode_usad8},
    {0xFFC0, 0x445A, "USADA8", decode_usada8},
    {0xFFC0, 0x445B, "USAT", decode_usat},
    {0xFFC0, 0x445C, "USAT16", decode_usat16},
    {0xFFC0, 0x445D, "USAX", decode_usax},
    {0xFFC0, 0x445E, "USUB16", decode_usub16},
    {0xFFC0, 0x445F, "USUB8", decode_usub8},
    {0xFFC0, 0x4460, "UXTAB", decode_uxtab},
    {0xFFC0, 0x4461, "UXTAB16", decode_uxtab16},
    {0xFFC0, 0x4462, "UXTAH", decode_uxtah},
    {0xFFC0, 0x4463, "VABA.s16", decode_vaba_s16},
    {0xFFC0, 0x4464, "VABD.s16", decode_vabd_s16},
    {0xFFC0, 0x4465, "VABS.s16", decode_vabs_s16},
    {0xFFC0, 0x4466, "VACGE.f32", decode_vacge_f32},
    {0xFFC0, 0x4467, "VACGT.f32", decode_vacgt_f32},
    {0xFFC0, 0x4468, "VACLE.f32", decode_vacle_f32},
    {0xFFC0, 0x4469, "VACLT.f32", decode_vaclt_f32},
    {0xFFC0, 0x446A, "VADD.i16", decode_vadd_i16},
    {0xFFC0, 0x446B, "VADDL.s16", decode_vaddl_s16},
    {0xFFC0, 0x446C, "VADDW.s16", decode_vaddw_s16},
    {0xFFC0, 0x446D, "VAND", decode_vand},
    {0xFFC0, 0x446E, "VBIC", decode_vbic},
    {0xFFC0, 0x446F, "VBIF", decode_vbif},
    {0xFFC0, 0x4470, "VBIT", decode_vbit},
    {0xFFC0, 0x4471, "VBSL", decode_vbsl},
    {0xFFC0, 0x4472, "VCEQ.i16", decode_vceq_i16},
    {0xFFC0, 0x4473, "VCGE.s16", decode_vcge_s16},
    {0xFFC0, 0x4474, "VCGT.s16", decode_vcgt_s16},
    {0xFFC0, 0x4475, "VCLE.s16", decode_vcle_s16},
    {0xFFC0, 0x4476, "VCLT.s16", decode_vclt_s16},
    {0xFFC0, 0x4477, "VCLZ.i16", decode_vclz_i16},
    {0xFFC0, 0x4478, "VCMP.f32", decode_vcmp_f32},
    {0xFFC0, 0x4479, "VCMPE.f32", decode_vcmpe_f32},
    {0xFFC0, 0x447A, "VCNT.8", decode_vcnt_8},
    {0xFFC0, 0x447B, "VDIV.f32", decode_vdiv_f32},
    {0xFFC0, 0x447C, "VDUP.16", decode_vdup_16},
    {0xFFC0, 0x447D, "VEOR", decode_veor},
    {0xFFC0, 0x447E, "VEXT.8", decode_vext_8},
    {0xFFC0, 0x447F, "VHADD.s16", decode_vhadd_s16},
    {0xFFC0, 0x4480, "VHSUB.s16", decode_vhsub_s16},
    {0xFFC0, 0x4481, "VLD1.16", decode_vld1_16},
    {0xFFC0, 0x4482, "VLD2.16", decode_vld2_16},
    {0xFFC0, 0x4483, "VLD3.16", decode_vld3_16},
    {0xFFC0, 0x4484, "VLD4.16", decode_vld4_16},
    {0xFFC0, 0x4485, "VLDM", decode_vldm},
    {0xFFC0, 0x4486, "VLLA", decode_vlla},
    {0xFFC0, 0x4487, "VMAX.s16", decode_vmax_s16},
    {0xFFC0, 0x4488, "VMAXA.s16", decode_vmaxa_s16},
    {0xFFC0, 0x4489, "VMIN.s16", decode_vmin_s16},
    {0xFFC0, 0x448A, "VMINA.s16", decode_vmina_s16},
    {0xFFC0, 0x448B, "VMLA.i16", decode_vmla_i16},
    {0xFFC0, 0x448C, "VMLAL.s16", decode_vmlal_s16},
    {0xFFC0, 0x448D, "VMLS.i16", decode_vmls_i16},
    {0xFFC0, 0x448E, "VMLSL.s16", decode_vmlsl_s16},
    {0xFFC0, 0x448F, "VMOV.i16", decode_vmov_i16},
    {0xFFC0, 0x4490, "VMOVL.s16", decode_vmovl_s16},
    {0xFFC0, 0x4491, "VMOVN.i16", decode_vmovn_i16},
    {0xFFC0, 0x4492, "VMRS", decode_vmrs},
    {0xFFC0, 0x4493, "VMSR", decode_vmsr},
    {0xFFC0, 0x4494, "VMUL.i16", decode_vmul_i16},
    {0xFFC0, 0x4495, "VMULL.s16", decode_vmull_s16},
    {0xFFC0, 0x4496, "VMVN", decode_vmvn},
    {0xFFC0, 0x4497, "VNEG.s16", decode_vneg_s16},
    {0xFFC0, 0x4498, "VNMLA.f32", decode_vnmla_f32},
    {0xFFC0, 0x4499, "VNMLS.f32", decode_vnmls_f32},
    {0xFFC0, 0x449A, "VNMLAL.s16", decode_vnmlal_s16},
    {0xFFC0, 0x449B, "VNMLSL.s16", decode_vnmlsl_s16},
    {0xFFC0, 0x449C, "VNMUL.f32", decode_vnmul_f32},
    {0xFFC0, 0x449D, "VPADAL.s16", decode_vpadal_s16},
    {0xFFC0, 0x449E, "VPADD.i16", decode_vpadd_i16},
    {0xFFC0, 0x449F, "VPADDL.s16", decode_vpaddl_s16},
    {0xFFC0, 0x44A0, "VPMIN.s16", decode_vpmin_s16},
    {0xFFC0, 0x44A1, "VPMAX.s16", decode_vpmax_s16},
    {0xFFC0, 0x44A2, "VQADD.s16", decode_vqadd_s16},
    {0xFFC0, 0x44A3, "VQSUB.s16", decode_vqsub_s16},
    {0xFFC0, 0x44A4, "VRADDHN.i16", decode_vraddhn_i16},
    {0xFFC0, 0x44A5, "VRECPE.u32", decode_vrecpe_u32},
    {0xFFC0, 0x44A6, "VRECPS.f32", decode_vrecps_f32},
    {0xFFC0, 0x44A7, "VRSQRTE.u32", decode_vrsqrte_u32},
    {0xFFC0, 0x44A8, "VRSQRTS.f32", decode_vrsqrts_f32},
    {0xFFC0, 0x44A9, "VSHL.i16", decode_vshl_i16},
    {0xFFC0, 0x44AA, "VSHLL.s16", decode_vshll_s16},
    {0xFFC0, 0x44AB, "VSHR.s16", decode_vshr_s16},
    {0xFFC0, 0x44AC, "VREV16.8", decode_vrev16_8},
    {0xFFC0, 0x44AD, "VREV32.8", decode_vrev32_8},
    {0xFFC0, 0x44AE, "VREV64.8", decode_vrev64_8},
    {0xFFC0, 0x44AF, "VSRI.16", decode_vsri_16},
    {0xFFC0, 0x44B0, "VSLI.16", decode_vsli_16},
    {0xFFC0, 0x44B1, "VSRA.s16", decode_vsra_s16},
    {0xFFC0, 0x44B2, "VSUB.i16", decode_vsub_i16},
    {0xFFC0, 0x44B3, "VSUBL.s16", decode_vsubl_s16},
    {0xFFC0, 0x44B4, "VSUBW.s16", decode_vsubw_s16},
    {0xFFC0, 0x44B5, "VSWP", decode_vswp},
    {0xFFC0, 0x44B6, "VTBL.8", decode_vtbl_8},
    {0xFFC0, 0x44B7, "VTBX.8", decode_vtbx_8},
    {0xFFC0, 0x44B8, "VTRN.16", decode_vtrn_16},
    {0xFFC0, 0x44B9, "VTST.8", decode_vtst_8},
    {0xFFC0, 0x44BA, "VUZP.16", decode_vuzp_16},
    {0xFFC0, 0x44BB, "VZIP.16", decode_vzip_16},
    {0x0000, 0x0000, "UNDEFINED", decode_default}
};

void disassemble(uint32_t insn, char *buf) {
    for (int i = 0; instructions[i].mask != 0; i++) {
        if ((insn & instructions[i].mask) == instructions[i].pattern) {
            instructions[i].decode(insn, buf);
            return;
        }
    }
    decode_default(insn, buf);
}

int main() {
    uint32_t code[] = {0x4401, 0x4463}; // Example: PKHTB, VABA.s16
    char output[32];
    uint32_t addr = 0x00000000;

    for (int i = 0; i < sizeof(code) / INSN_SIZE; i++) {
        disassemble(code[i], output);
        printf("%08x: %s\n", addr, output);
        addr += INSN_SIZE;
    }

    return 0;
}
