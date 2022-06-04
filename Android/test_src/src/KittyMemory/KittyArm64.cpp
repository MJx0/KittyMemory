#include "KittyArm64.h"

// refs to
// https://github.com/CAS-Atlantic/AArch64-Encoding
// https://github.com/bminor/binutils-gdb
// https://github.com/capstone-engine/capstone
// https://github.com/qemu/QEMU
// https://reverseengineering.stackexchange.com/questions/15418/getting-function-address-by-reading-adrp-and-add-instruction-values

namespace KittyArm64
{

	int32_t bit_from(uint32_t insn, int pos)
	{
		return ((1 << pos) & insn) >> pos;
	}

	int32_t bits_from(uint32_t insn, int pos, int l)
	{
		return (insn >> pos) & ((1 << l) - 1);
	}

	bool is_insn_adr(uint32_t insn)
	{
		return (insn & 0x9F000000) == 0x10000000;
	}

	bool is_insn_adrp(uint32_t insn)
	{
		return (insn & 0x9F000000) == 0x90000000;
	}

	// decode adr/adrp
	bool decode_adr_imm(uint32_t insn, int64_t *imm)
	{
		const int mask19 = (1 << 19) - 1;
		const int mask2 = 3;

		if (is_insn_adr(insn) || is_insn_adrp(insn))
		{
			// 21-bit imm encoded in adrp.
			uint64_t imm_val = ((insn >> 29) & mask2) | (((insn >> 5) & mask19) << 2);
			// Retrieve msb of 21-bit-signed imm for sign extension.
			uint64_t msbt = (imm_val >> 20) & 1;

			if (!is_insn_adr(insn))
			{
				// Real value is imm multiplied by 4k. Value now has 33-bit information.
				imm_val <<= 12;
			}

			// Sign extend to 64-bit by repeating msbt 31 (64-33) times and merge it
			// with value.
			*imm = ((((uint64_t)(1) << 32) - msbt) << 33) | imm_val;

			return true;
		}

		return false;
	}

	/*
	 *  31 30 29 28         23 22 21         10 9   5 4   0
	 * +--+--+--+-------------+--+-------------+-----+-----+
	 * |sf|op| S| 1 0 0 0 1 0 |sh|    imm12    |  Rn | Rd  |
	 * +--+--+--+-------------+--+-------------+-----+-----+
	 *
	 *    sf: 0 -> 32bit, 1 -> 64bit
	 *    op: 0 -> add  , 1 -> sub
	 *     S: 1 -> set flags
	 *    sh: 1 -> LSL imm by 12
	 */

	int32_t decode_addsub_imm(uint32_t insn)
	{
		int32_t imm12 = bits_from(insn, 10, 12);

		bool shift = bit_from(insn, 22) == 1;

		if (shift)
		{
			imm12 <<= 12;
		}

		return imm12;
	}

	bool is_insn_ld(uint32_t insn)
	{
		// L bit
		return bit_from(insn, 22) == 1;
	}

	bool is_insn_ldst(uint32_t insn)
	{
		return (insn & 0x0a000000) == 0x08000000;
	}

	bool is_insn_ldst_uimm(uint32_t insn)
	{
		return (insn & 0x3b000000) == 0x39000000;
	}

	// decode Load/store unsigned immediate
	bool decode_ldrstr_uimm(uint32_t insn, int32_t *imm12)
	{
		if (is_insn_ldst_uimm(insn))
		{
			*imm12 = bits_from(insn, 10, 12);
			if (*imm12)
			{
				*imm12 <<= 3;
			}

			return true;
		}

		return false;
	}

}