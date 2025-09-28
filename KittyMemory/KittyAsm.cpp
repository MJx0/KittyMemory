#include "KittyAsm.hpp"

// refs to
// https://github.com/CAS-Atlantic/AArch64-Encoding
// https://github.com/bminor/binutils-gdb
// https://github.com/capstone-engine/capstone
// https://github.com/qemu/QEMU
// https://reverseengineering.stackexchange.com/questions/15418/getting-function-address-by-reading-adrp-and-add-instruction-values
// https://stackoverflow.com/questions/41906688/what-are-the-semantics-of-adrp-and-adrl-instructions-in-arm-assembly

namespace KittyAsm
{
    uint32_t bits(uint32_t v, int hi, int lo)
    {
        if (hi < lo)
            return 0u;

        int width = hi - lo + 1;
        if (width >= 32)
            return v >> lo;

        uint32_t mask = (width == 32) ? 0xFFFFFFFFu : ((1u << width) - 1u);
        return (v >> lo) & mask;
    }
} // namespace KittyAsm

using namespace KittyAsm;

namespace KittyArm32
{
    EKittyInsnTypeArm32 decodeInsnType(uint32_t instr)
    {
        if ((instr & 0x0C000000) == 0x00000000)
        {
            if ((instr & 0x01E00000) == 0x00800000)
                return bits(instr, 19, 16) == 15 ? EKittyInsnTypeArm32::ADR : EKittyInsnTypeArm32::ADD;

            if ((instr & 0x01E00000) == 0x00400000)
                return bits(instr, 19, 16) == 15 ? EKittyInsnTypeArm32::ADR : EKittyInsnTypeArm32::SUB;

            if ((instr & 0x01E00000) == 0x01A00000)
                return EKittyInsnTypeArm32::MOV;
        }

        if ((instr & 0x0FF00000) == 0x02800000)
            return EKittyInsnTypeArm32::LDR_LITERAL;

        if ((instr & 0x0C500000) == 0x04100000)
            return bits(instr, 19, 16) == 15 ? EKittyInsnTypeArm32::LDR_LITERAL : EKittyInsnTypeArm32::LDR;

        if ((instr & 0x0C500000) == 0x04000000)
            return EKittyInsnTypeArm32::STR;

        if ((instr & 0x0C500000) == 0x04500000)
            return bits(instr, 19, 16) == 15 ? EKittyInsnTypeArm32::LDR_LITERAL : EKittyInsnTypeArm32::LDRB;

        if ((instr & 0x0C500000) == 0x04400000)
            return EKittyInsnTypeArm32::STRB;

        if ((instr & 0x0F1000F0) == 0x011000B0)
            return EKittyInsnTypeArm32::LDRH;

        if ((instr & 0x0F1000F0) == 0x010000B0)
            return EKittyInsnTypeArm32::STRH;

        if ((instr & 0x0F1000F0) == 0x011000D0)
            return EKittyInsnTypeArm32::LDRSB;

        if ((instr & 0x0F1000F0) == 0x011000F0)
            return EKittyInsnTypeArm32::LDRSH;

        if ((instr & 0x0F000000) == 0x0A000000)
            return bits(instr, 31, 28) == 0xE ? EKittyInsnTypeArm32::B : EKittyInsnTypeArm32::B_COND;

        if ((instr & 0x0F000000) == 0x0B000000)
            return EKittyInsnTypeArm32::BL;

        return EKittyInsnTypeArm32::UNKNOWN;
    }

    KittyInsnArm32 decodeInsn(uint32_t instr, uint32_t address)
    {
        KittyInsnArm32 insn{};

        EKittyInsnTypeArm32 insn_type = decodeInsnType(instr);
        if (insn_type == EKittyInsnTypeArm32::UNKNOWN)
            return insn;

        insn.bytes = instr;
        insn.address = address;
        insn.type = insn_type;
        insn.typeStr = typeToString(insn_type);

        switch (insn_type)
        {
        case EKittyInsnTypeArm32::UNKNOWN:
            return insn;

        case EKittyInsnTypeArm32::ADD:
        case EKittyInsnTypeArm32::SUB:
        case EKittyInsnTypeArm32::MOV:
        case EKittyInsnTypeArm32::ADR:
        {
            bool I = bit(instr, 25);
            uint32_t rn = bits(instr, 19, 16);
            uint32_t rd = bits(instr, 15, 12);
            uint32_t imm12 = bits(instr, 11, 0);
            uint32_t imm8 = bits(imm12, 7, 0);
            uint32_t rot = bits(imm12, 11, 8) * 2u;
            uint32_t imm32 = ror32(imm8, rot);
            insn.rd = regName(rd);

            if (insn_type != EKittyInsnTypeArm32::MOV)
                insn.rn = regName(rn);

            if (!I)
                insn.rt = regName(imm12);
            else
                insn.immediate = I ? imm32 : 0;

            if (rn == 15)
                insn.target = address + 8u + insn.immediate;

            break;
        }

        case EKittyInsnTypeArm32::LDRH:
        case EKittyInsnTypeArm32::LDRSH:
        case EKittyInsnTypeArm32::LDRSB:
        case EKittyInsnTypeArm32::STRH:
        {
            bool U = bit(instr, 23);
            uint32_t rn = bits(instr, 19, 16);
            uint32_t rd = bits(instr, 15, 12);
            uint32_t immH = bits(instr, 11, 8);
            uint32_t immL = bits(instr, 3, 0);
            uint32_t offset = (immH << 4) | immL;
            insn.rd = regName(rd);
            insn.rn = regName(rn);
            insn.immediate = U ? offset : -((int32_t)offset);
            break;
        }

        case EKittyInsnTypeArm32::LDR:
        case EKittyInsnTypeArm32::LDRB:
        case EKittyInsnTypeArm32::STR:
        case EKittyInsnTypeArm32::STRB:
        case EKittyInsnTypeArm32::LDR_LITERAL:
        {
            bool U = bit(instr, 23);
            uint32_t rn = bits(instr, 19, 16);
            uint32_t rd = bits(instr, 15, 12);
            uint32_t imm12 = bits(instr, 11, 0);
            insn.rd = regName(rd);
            insn.rn = regName(rn);
            insn.immediate = U ? imm12 : -((int32_t)imm12);
            // PC
            if (rn == 15)
            {
                insn.target = address + 8u + insn.immediate;
            }
            break;
        }

        case EKittyInsnTypeArm32::B:
        case EKittyInsnTypeArm32::BL:
        case EKittyInsnTypeArm32::B_COND:
        {
            uint32_t cond = bits(instr, 31, 28);
            uint32_t imm24 = bits(instr, 23, 0);
            int32_t simm = signExtend(imm24, 24) << 2;
            insn.immediate = simm;
            insn.target = address + 8u + simm;
            if (insn_type == EKittyInsnTypeArm32::B_COND)
            {
                insn.cond = branchCondName(cond);
            }
            break;
        }
        }

        return insn;
    }

    std::string typeToString(EKittyInsnTypeArm32 t)
    {
#define CASE(x)                                                                                                        \
    case EKittyInsnTypeArm32::x:                                                                                       \
        return #x;
        switch (t)
        {
            CASE(UNKNOWN)
            CASE(ADR)
            CASE(ADD)
            CASE(SUB)
            CASE(MOV)
            CASE(LDR)
            CASE(STR)
            CASE(LDRB)
            CASE(STRB)
            CASE(LDRH)
            CASE(STRH)
            CASE(LDRSH)
            CASE(LDRSB)
            CASE(LDR_LITERAL)
            CASE(B)
            CASE(BL)
            CASE(B_COND)
        }
#undef CASE
        return "UNKNOWN";
    }
} // namespace KittyArm32

namespace KittyArm64
{
    EKittyInsnTypeArm64 decodeInsnType(uint32_t instr)
    {
        // ADR
        if ((instr & 0x9F000000u) == 0x10000000u)
        {
            return EKittyInsnTypeArm64::ADR;
        }
        // ADRP
        if ((instr & 0x9F000000u) == 0x90000000u)
        {
            return EKittyInsnTypeArm64::ADRP;
        }

        // ADD
        if ((instr & 0xFF000000u) == 0x11000000u || (instr & 0xFF000000u) == 0x91000000u)
        {
            return EKittyInsnTypeArm64::ADD;
        }
        // SUB
        if ((instr & 0xFF000000u) == 0x51000000u || (instr & 0xFF000000u) == 0xD1000000u)
        {
            return EKittyInsnTypeArm64::SUB;
        }

        // MOVZ
        if ((instr & 0x7F800000u) == 0x52800000u)
        {
            return EKittyInsnTypeArm64::MOVZ;
        }
        // MOVK
        if ((instr & 0x7F800000u) == 0x72800000u)
        {
            return EKittyInsnTypeArm64::MOVK;
        }
        // MOVN
        if ((instr & 0x7F800000u) == 0x12800000u)
        {
            return EKittyInsnTypeArm64::MOVN;
        }

        // Load/Store (immediate offset)
        {
            if ((instr & 0xFFC00000) == 0xF9400000)
                return EKittyInsnTypeArm64::LDR;
            if ((instr & 0xFFC00000) == 0xF9000000)
                return EKittyInsnTypeArm64::STR;
            if ((instr & 0xFFC00000) == 0xB9400000)
                return EKittyInsnTypeArm64::LDRW;
            if ((instr & 0xFFC00000) == 0xB9000000)
                return EKittyInsnTypeArm64::STRW;

            if ((instr & 0xFFC00000) == 0x39400000)
                return EKittyInsnTypeArm64::LDRB;
            if ((instr & 0xFFC00000) == 0x39000000)
                return EKittyInsnTypeArm64::STRB;

            if ((instr & 0xFFC00000) == 0x79400000)
                return EKittyInsnTypeArm64::LDRH;
            if ((instr & 0xFFC00000) == 0x79000000)
                return EKittyInsnTypeArm64::STRH;

            if ((instr & 0xFFC00000) == 0x39C00000 || (instr & 0xFFC00000) == 0x39800000)
                return EKittyInsnTypeArm64::LDRSB;
            if ((instr & 0xFFC00000) == 0x79C00000 || (instr & 0xFFC00000) == 0x79800000)
                return EKittyInsnTypeArm64::LDRSH;
            if ((instr & 0xFFC00000) == 0xB9800000)
                return EKittyInsnTypeArm64::LDRSW;
        }

        // Load/Store (post-indexed)
        {
            if ((instr & 0xFFC00C00) == 0xB8400400 || (instr & 0xFFC00C00) == 0xF8400400)
                return EKittyInsnTypeArm64::LDR_POST;
            if ((instr & 0xFFC00C00) == 0xB8000400 || (instr & 0xFFC00C00) == 0xF8000400)
                return EKittyInsnTypeArm64::STR_POST;

            if ((instr & 0xFFC00C00) == 0x38400400)
                return EKittyInsnTypeArm64::LDRB_POST;
            if ((instr & 0xFFC00C00) == 0x38000400)
                return EKittyInsnTypeArm64::STRB_POST;

            if ((instr & 0xFFC00C00) == 0x78400400)
                return EKittyInsnTypeArm64::LDRH_POST;
            if ((instr & 0xFFC00C00) == 0x78000400)
                return EKittyInsnTypeArm64::STRH_POST;

            if ((instr & 0xFFC00C00) == 0x38C00400 || (instr & 0xFFC00C00) == 0x38800400)
                return EKittyInsnTypeArm64::LDRSB_POST;
            if ((instr & 0xFFC00C00) == 0x78C00400 || (instr & 0xFFC00C00) == 0x78800400)
                return EKittyInsnTypeArm64::LDRSH_POST;
            if ((instr & 0xFFC00C00) == 0xB8800400)
                return EKittyInsnTypeArm64::LDRSW_POST;
        }

        // Load/Store (pre-indexed)
        {
            if ((instr & 0xFFC00C00) == 0xB8400C00 || (instr & 0xFFC00C00) == 0xF8400C00)
                return EKittyInsnTypeArm64::LDR_PRE;
            if ((instr & 0xFFC00C00) == 0xB8000C00 || (instr & 0xFFC00C00) == 0xF8000C00)
                return EKittyInsnTypeArm64::STR_PRE;

            if ((instr & 0xFFC00C00) == 0x38400C00)
                return EKittyInsnTypeArm64::LDRB_PRE;
            if ((instr & 0xFFC00C00) == 0x38000C00)
                return EKittyInsnTypeArm64::STRB_PRE;

            if ((instr & 0xFFC00C00) == 0x78400C00)
                return EKittyInsnTypeArm64::LDRH_PRE;
            if ((instr & 0xFFC00C00) == 0x78000C00)
                return EKittyInsnTypeArm64::STRH_PRE;

            if ((instr & 0xFFC00C00) == 0x38C00C00 || (instr & 0xFFC00C00) == 0x38800C00)
                return EKittyInsnTypeArm64::LDRSB_PRE;
            if ((instr & 0xFFC00C00) == 0x78C00C00 || (instr & 0xFFC00C00) == 0x78800C00)
                return EKittyInsnTypeArm64::LDRSH_PRE;
            if ((instr & 0xFFC00C00) == 0xB8800C00)
                return EKittyInsnTypeArm64::LDRSW_PRE;
        }

        // === Load/Store (unscaled)
        {
            if ((instr & 0xFFC00000) == 0xF8400000)
                return EKittyInsnTypeArm64::LDUR;
            if ((instr & 0xFFC00000) == 0xF8000000)
                return EKittyInsnTypeArm64::STUR;
            if ((instr & 0xFFC00000) == 0xB8400000)
                return EKittyInsnTypeArm64::LDURW;
            if ((instr & 0xFFC00000) == 0xB8000000)
                return EKittyInsnTypeArm64::STURW;
            if ((instr & 0xFFC00000) == 0x38400000)
                return EKittyInsnTypeArm64::LDURB;
            if ((instr & 0xFFC00000) == 0x38000000)
                return EKittyInsnTypeArm64::STURB;
            if ((instr & 0xFFC00000) == 0x78400000)
                return EKittyInsnTypeArm64::LDURH;
            if ((instr & 0xFFC00000) == 0x78000000)
                return EKittyInsnTypeArm64::STURH;
            if ((instr & 0xFFC00000) == 0xB8800000)
                return EKittyInsnTypeArm64::LDURSW;
            if ((instr & 0xFFC00000) == 0x38800000u || (instr & 0xFFC00000) == 0x38C00000u)
                return EKittyInsnTypeArm64::LDURSB;
            if ((instr & 0xFFC00000) == 0x78800000u || (instr & 0xFFC00000) == 0x78C00000u)
                return EKittyInsnTypeArm64::LDURSH;
        }

        // Load/Store (Literal)
        {
            if ((instr & 0xFFC00000) == 0x18000000)
                return EKittyInsnTypeArm64::LDRW_LITERAL;
            if ((instr & 0xFFC00000) == 0x58000000)
                return EKittyInsnTypeArm64::LDR_LITERAL;
            if ((instr & 0xFFC00000) == 0x98000000)
                return EKittyInsnTypeArm64::LDRSW_LITERAL;
        }

        // B
        if ((instr & 0xFC000000u) == 0x14000000u)
        {
            return EKittyInsnTypeArm64::B;
        }

        // BL
        if ((instr & 0xFC000000u) == 0x94000000u)
        {
            return EKittyInsnTypeArm64::BL;
        }

        // B.Cond
        if ((instr & 0xFF000010u) == 0x54000000u)
        {
            return EKittyInsnTypeArm64::B_COND;
        }

        // CBZ/CBNZ
        {
            if ((instr & 0x7F000000u) == 0x34000000u)
                return EKittyInsnTypeArm64::CBZ;
            if ((instr & 0x7F000000u) == 0x35000000u)
                return EKittyInsnTypeArm64::CBNZ;
        }

        // TBZ/TBNZ
        {
            if ((instr & 0x7F000000u) == 0x36000000u)
                return EKittyInsnTypeArm64::TBZ;
            if ((instr & 0x7F000000u) == 0x37000000u)
                return EKittyInsnTypeArm64::TBNZ;
        }

        return EKittyInsnTypeArm64::UNKNOWN;
    }

    KittyInsnArm64 decodeInsn(uint32_t instr, uint64_t address)
    {
        KittyInsnArm64 insn{};

        EKittyInsnTypeArm64 insn_type = decodeInsnType(instr);
        if (insn_type == EKittyInsnTypeArm64::UNKNOWN)
            return insn;

        insn.bytes = instr;
        insn.address = address;
        insn.type = insn_type;
        insn.typeStr = typeToString(insn_type);

        switch (insn_type)
        {
        case EKittyInsnTypeArm64::UNKNOWN:
            return insn;

        case EKittyInsnTypeArm64::ADR:
        case EKittyInsnTypeArm64::ADRP:
        {
            uint32_t rd = bits(instr, 4, 0);
            uint32_t immlo = bits(instr, 30, 29);
            uint32_t immhi = bits(instr, 23, 5);
            uint64_t imm = (uint64_t)((immhi << 2) | immlo);
            insn.rd = xRegName(rd, false);
            if (insn_type == EKittyInsnTypeArm64::ADR)
            {

                int64_t simm = signExtend(imm, 21);
                insn.immediate = simm;
                insn.target = address + simm;
            }
            else
            {
                int64_t simm = signExtend(imm, 21) << 12;
                insn.immediate = simm;
                insn.target = (address & ~0xFFFULL) + simm;
            }
            break;
        }

        case EKittyInsnTypeArm64::MOVZ:
        case EKittyInsnTypeArm64::MOVK:
        case EKittyInsnTypeArm64::MOVN:
        {
            bool is64 = bit(instr, 31);
            uint32_t rd = bits(instr, 4, 0);
            uint32_t imm16 = bits(instr, 20, 5);
            uint32_t hw = bits(instr, 22, 21);
            uint64_t imm = (uint64_t)(imm16 << (hw * 16));
            insn.rd = is64 ? xRegName(rd, false) : wRegName(rd, false);
            insn.immediate = insn_type != EKittyInsnTypeArm64::MOVN ? imm : (int64_t)~imm;
            break;
        }

        case EKittyInsnTypeArm64::ADD:
        case EKittyInsnTypeArm64::SUB:
        {
            bool is64 = bit(instr, 31);
            uint32_t rd = bits(instr, 4, 0);
            uint32_t rn = bits(instr, 9, 5);
            uint32_t imm12 = bits(instr, 21, 10);
            uint32_t sh = bits(instr, 23, 22);
            uint64_t imm = (uint64_t)(sh == 1 ? imm12 << 12 : imm12);
            insn.rd = is64 ? xRegName(rd, false) : wRegName(rd, false);
            insn.rn = is64 ? xRegName(rn, true) : wRegName(rn, true);
            insn.immediate = imm;
            break;
        }

        // ldr/str uimm12
        case EKittyInsnTypeArm64::LDR:
        case EKittyInsnTypeArm64::STR:
        case EKittyInsnTypeArm64::LDRW:
        case EKittyInsnTypeArm64::STRW:
        case EKittyInsnTypeArm64::LDRB:
        case EKittyInsnTypeArm64::STRB:
        case EKittyInsnTypeArm64::LDRH:
        case EKittyInsnTypeArm64::STRH:
        case EKittyInsnTypeArm64::LDRSB:
        case EKittyInsnTypeArm64::LDRSH:
        case EKittyInsnTypeArm64::LDRSW:
        {
            uint32_t size = bits(instr, 31, 30);
            uint32_t rn = bits(instr, 9, 5);
            uint32_t rt = bits(instr, 4, 0);
            uint32_t imm12 = bits(instr, 21, 10);
            uint64_t offset = (uint64_t)(imm12 << size);
            insn.rn = xRegName(rn, true);
            insn.rt = size == 3 ? xRegName(rt, false) : wRegName(rt, false);
            insn.immediate = offset;
            break;
        }

        // ldr/str post/pre indexed imm9
        case EKittyInsnTypeArm64::LDR_PRE:
        case EKittyInsnTypeArm64::STR_PRE:
        case EKittyInsnTypeArm64::LDRB_PRE:
        case EKittyInsnTypeArm64::STRB_PRE:
        case EKittyInsnTypeArm64::LDRH_PRE:
        case EKittyInsnTypeArm64::STRH_PRE:
        case EKittyInsnTypeArm64::LDRSB_PRE:
        case EKittyInsnTypeArm64::LDRSH_PRE:
        case EKittyInsnTypeArm64::LDRSW_PRE:
        case EKittyInsnTypeArm64::LDR_POST:
        case EKittyInsnTypeArm64::STR_POST:
        case EKittyInsnTypeArm64::LDRB_POST:
        case EKittyInsnTypeArm64::STRB_POST:
        case EKittyInsnTypeArm64::LDRH_POST:
        case EKittyInsnTypeArm64::STRH_POST:
        case EKittyInsnTypeArm64::LDRSB_POST:
        case EKittyInsnTypeArm64::LDRSH_POST:
        case EKittyInsnTypeArm64::LDRSW_POST:
        {
            uint32_t size = bits(instr, 31, 30);
            uint32_t rn = bits(instr, 9, 5);
            uint32_t rt = bits(instr, 4, 0);
            uint32_t imm9 = bits(instr, 20, 12);
            int64_t simm = signExtend(imm9, 9);
            insn.rn = xRegName(rn, true);
            insn.rt = size == 3 ? xRegName(rt, false) : wRegName(rt, false);
            insn.immediate = simm;
            break;
        }

        // imm9 unscaled ldr/str
        case EKittyInsnTypeArm64::LDUR:
        case EKittyInsnTypeArm64::STUR:
        case EKittyInsnTypeArm64::LDURW:
        case EKittyInsnTypeArm64::STURW:
        case EKittyInsnTypeArm64::LDURB:
        case EKittyInsnTypeArm64::STURB:
        case EKittyInsnTypeArm64::LDURH:
        case EKittyInsnTypeArm64::STURH:
        case EKittyInsnTypeArm64::LDURSB:
        case EKittyInsnTypeArm64::LDURSH:
        case EKittyInsnTypeArm64::LDURSW:
        {
            uint32_t size = bits(instr, 31, 30);
            uint32_t rn = bits(instr, 9, 5);
            uint32_t rt = bits(instr, 4, 0);
            uint32_t imm9 = bits(instr, 20, 12);
            int64_t simm = signExtend(imm9, 9);
            insn.rn = xRegName(rn, true);
            insn.rt = size == 3 ? xRegName(rt, false) : wRegName(rt, false);
            insn.immediate = simm;
            break;
        }

        case EKittyInsnTypeArm64::LDR_LITERAL:
        case EKittyInsnTypeArm64::LDRW_LITERAL:
        case EKittyInsnTypeArm64::LDRSW_LITERAL:
        {
            uint32_t size = bits(instr, 31, 30);
            uint32_t rt = bits(instr, 4, 0);
            uint32_t imm19 = bits(instr, 23, 5);
            int64_t simm = signExtend(imm19, 19) << 2;
            insn.rn = "PC";
            insn.rt = size == 3 ? xRegName(rt, false) : wRegName(rt, false);
            insn.immediate = simm;
            insn.target = address + simm;
            break;
        }

        case EKittyInsnTypeArm64::B:
        case EKittyInsnTypeArm64::BL:
        {
            uint32_t imm26 = bits(instr, 25, 0);
            int64_t simm = signExtend(imm26, 26) << 2;
            insn.immediate = simm;
            insn.target = address + simm;
            break;
        }

        case EKittyInsnTypeArm64::B_COND:
        {
            uint32_t cond = bits(instr, 3, 0);
            uint32_t imm19 = bits(instr, 23, 5);
            int64_t simm = signExtend(imm19, 19) << 2;
            insn.immediate = simm;
            insn.target = address + simm;
            insn.cond = branchCondName(cond);
            break;
        }

        case EKittyInsnTypeArm64::CBZ:
        case EKittyInsnTypeArm64::CBNZ:
        {
            bool is64 = bit(instr, 32);
            uint32_t imm19 = bits(instr, 23, 5);
            uint32_t rt = bits(instr, 4, 0);
            int64_t simm = signExtend(imm19, 19) << 2;
            insn.rt = is64 ? xRegName(rt, false) : wRegName(rt, false);
            insn.immediate = simm;
            insn.target = address + simm;
            break;
        }

        case EKittyInsnTypeArm64::TBZ:
        case EKittyInsnTypeArm64::TBNZ:
        {
            bool is64 = bit(instr, 32);
            uint32_t rt = bits(instr, 4, 0);
            uint32_t bit5 = (bits(instr, 31, 31) & 1) << 5;
            uint32_t bit_lo = bits(instr, 23, 19);
            uint32_t bitpos = bit5 | bit_lo;
            uint32_t imm14 = bits(instr, 18, 5);
            int64_t simm = signExtend(imm14, 14) << 2;
            insn.rt = is64 ? xRegName(rt, false) : wRegName(rt, false);
            insn.immediate = simm;
            insn.bitpos = bitpos;
            insn.target = address + simm;
            break;
        }
        }

        return insn;
    }

    std::string typeToString(EKittyInsnTypeArm64 t)
    {
#define CASE(x)                                                                                                        \
    case EKittyInsnTypeArm64::x:                                                                                       \
        return #x;
        switch (t)
        {
            CASE(UNKNOWN)
            CASE(ADR)
            CASE(ADRP)
            CASE(ADD)
            CASE(SUB)
            CASE(MOVZ)
            CASE(MOVN)
            CASE(MOVK)
            CASE(LDR)
            CASE(STR)
            CASE(LDRW)
            CASE(STRW)
            CASE(LDRB)
            CASE(STRB)
            CASE(LDRH)
            CASE(STRH)
            CASE(LDRSB)
            CASE(LDRSH)
            CASE(LDRSW)
            CASE(LDR_PRE)
            CASE(STR_PRE)
            CASE(LDRB_PRE)
            CASE(STRB_PRE)
            CASE(LDRH_PRE)
            CASE(STRH_PRE)
            CASE(LDRSB_PRE)
            CASE(LDRSH_PRE)
            CASE(LDRSW_PRE)
            CASE(LDR_POST)
            CASE(STR_POST)
            CASE(LDRB_POST)
            CASE(STRB_POST)
            CASE(LDRH_POST)
            CASE(STRH_POST)
            CASE(LDRSB_POST)
            CASE(LDRSH_POST)
            CASE(LDRSW_POST)
            CASE(LDUR)
            CASE(STUR)
            CASE(LDURW)
            CASE(STURW)
            CASE(LDURB)
            CASE(STURB)
            CASE(LDURH)
            CASE(STURH)
            CASE(LDURSB)
            CASE(LDURSH)
            CASE(LDURSW)
            CASE(LDR_LITERAL)
            CASE(LDRW_LITERAL)
            CASE(LDRSW_LITERAL)
            CASE(B)
            CASE(BL)
            CASE(B_COND)
            CASE(CBZ)
            CASE(CBNZ)
            CASE(TBZ)
            CASE(TBNZ)
        }
#undef CASE
        return "UNKNOWN";
    }
} // namespace KittyArm64