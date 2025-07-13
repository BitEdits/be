objects := be.o editor.o \
	hex/hex.o dasm/dasm.o term/buffer.o term/terminal.o \
	arch/x86/insnsd.o arch/x86/insnsa.o arch/x86/insnsb.o arch/x86/insnsn.o arch/x86/disasm.o \
	arch/x86/regdis.o arch/x86/regs.o arch/x86/regflags.o arch/x86/regvals.o \
	arch/x86/iflag.o arch/x86/sync.o arch/x86/disp8.o arch/x86/nctype.o arch/x86/readnum.o  \
	arch/x86/common.o arch/x86/alloc.o arch/x86/string.o \
	arch/x86/warnings.o arch/x86/error.o arch/x86/ver.o \
	arch/arm64/BranchExcSys.o arch/arm64/DataProcessingImmediate.o arch/arm64/LoadsAndStores.o \
	arch/arm64/bits.o arch/arm64/strext.o \
	arch/arm64/DataProcessingFloatingPoint.o arch/arm64/DataProcessingRegister.o \
	arch/arm64/armadillo.o arch/arm64/instruction.o arch/arm64/utils.o \
	arch/arm32/armv7.o \
	arch/riscv/riscv-disas.o \
	arch/ppc/ppc_disasm.o \
	arch/m68k/dis68k.o \
	arch/sh4/sh4.o \
	arch/nv/core-as.o arch/nv/ctx.o arch/nv/falcon.o arch/nv/gk110.o arch/nv/macro.o arch/nv/vp1.o arch/nv/hash.o \
	arch/nv/envyas.o arch/nv/g80.o arch/nv/gm107.o arch/nv/nv.o arch/nv/vuc.o arch/nv/xtensa.o arch/nv/astr.o arch/nv/colors.o \
	arch/nv/core-dis.o arch/nv/core.o arch/nv/envydis.o arch/nv/gf100.o arch/nv/hwsq.o arch/nv/vcomp.o arch/nv/mask.o \
	arch/nv/varinfo.o arch/nv/vardata.o arch/nv/symtab.o arch/nv/easm.o arch/nv/aprintf.o arch/nv/easm_xfrm.o arch/nv/easm_print.o \
	arch/mips/mips-rsp.o \
	arch/pdp11/pdp11.o
.PHONY: all
all: be
%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<
be: $(objects)
	$(CC) -o $@ $^ $(LDFLAGS)
.PHONY: install
install:
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m0755 be $(DESTDIR)$(PREFIX)/bin
.PHONY: clean
clean:
	$(RM) $(objects) $(objects:.o=.d) be
