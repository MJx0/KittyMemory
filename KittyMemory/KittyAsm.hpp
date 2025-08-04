#pragma once

#include <cstdio>
#include <cstdint>
#include <string>

namespace KittyAsm
{
	int32_t bit_from(uint32_t insn, int pos);
	int32_t bits_from(uint32_t insn, int pos, int l);
}

namespace KittyArm64
{
	bool is_insn_adr(uint32_t insn);

	bool is_insn_adrp(uint32_t insn);

	bool decode_adr_imm(uint32_t insn, int64_t *imm);

	int32_t decode_addsub_imm(uint32_t insn);

	bool is_insn_ld(uint32_t insn);

	bool is_insn_ldst(uint32_t insn);

	bool is_insn_ldst_uimm(uint32_t insn);

	bool decode_ldrstr_uimm(uint32_t insn, int32_t *offset);

}

namespace KittyArm
{
	int32_t decode_ldr_literal(uint32_t insn);
}