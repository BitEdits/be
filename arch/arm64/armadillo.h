#ifndef _ARMADILLO_H_
#define _ARMADILLO_H_

#include <stdint.h>
#include "adefs.h"

int ArmadilloDisassemble(unsigned int opcode, unsigned long PC, struct ad_insn **out);
int ArmadilloDone(struct ad_insn **insn);
char *decodeARM(unsigned long int start, char *outbuf, int *outlen, unsigned long int offset0);

#endif
