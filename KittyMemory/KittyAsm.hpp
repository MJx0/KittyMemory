#pragma once

#include <cstdint>
#include <string>

enum class EKittyInsnTypeArm32
{
    UNKNOWN,
    ADR,
    ADD,
    SUB,
    MOV,
    LDR,
    STR,
    LDRB,
    STRB,
    LDRH,
    STRH,
    LDRSB,
    LDRSH,
    LDR_LITERAL,
    B,
    BL,
    B_COND
};

struct KittyInsnArm32
{
    EKittyInsnTypeArm32 type;
    std::string typeStr;
    std::string rd, rn, rt;
    uint32_t bytes;
    uint32_t address;
    int32_t immediate;
    uint32_t target;
    std::string cond;
    KittyInsnArm32() : type(EKittyInsnTypeArm32::UNKNOWN), bytes(0), address(0), immediate(0), target(0)
    {
    }
    inline bool isValid() const
    {
        return bytes != 0 && type != EKittyInsnTypeArm32::UNKNOWN;
    }
};

enum class EKittyInsnTypeArm64
{
    UNKNOWN,
    ADR,
    ADRP,
    ADD,
    SUB,
    MOVZ,
    MOVN,
    MOVK,
    LDR,
    STR,
    LDRW,
    STRW,
    LDRB,
    STRB,
    LDRH,
    STRH,
    LDRSB,
    LDRSH,
    LDRSW,
    LDR_PRE,
    STR_PRE,
    LDRB_PRE,
    STRB_PRE,
    LDRH_PRE,
    STRH_PRE,
    LDRSB_PRE,
    LDRSH_PRE,
    LDRSW_PRE,
    LDR_POST,
    STR_POST,
    LDRB_POST,
    STRB_POST,
    LDRH_POST,
    STRH_POST,
    LDRSB_POST,
    LDRSH_POST,
    LDRSW_POST,
    LDUR,
    STUR,
    LDURW,
    STURW,
    LDURB,
    STURB,
    LDURH,
    STURH,
    LDURSB,
    LDURSH,
    LDURSW,
    LDR_LITERAL,
    LDRW_LITERAL,
    LDRSW_LITERAL,
    B,
    BL,
    B_COND,
    CBZ,
    CBNZ,
    TBZ,
    TBNZ,
};

struct KittyInsnArm64
{
    EKittyInsnTypeArm64 type = EKittyInsnTypeArm64::UNKNOWN;
    std::string typeStr;
    std::string rd, rn, rt;
    uint32_t bytes;
    uint64_t address;
    int64_t immediate;
    int64_t bitpos;
    uint64_t target;
    std::string cond;
    KittyInsnArm64() : type(EKittyInsnTypeArm64::UNKNOWN), bytes(0), address(0), immediate(0), bitpos(0), target(0)
    {
    }
    inline bool isValid() const
    {
        return bytes != 0 && type != EKittyInsnTypeArm64::UNKNOWN;
    }
};

namespace KittyAsm
{
    uint32_t bits(uint32_t v, int hi, int lo);

    inline bool bit(uint32_t v, int pos)
    {
        return bits(v, pos, pos) != 0;
    }

    inline uint32_t ror32(uint32_t value, unsigned int shift)
    {
        shift &= 31u;
        return (value >> shift) | (value << ((32 - shift) & 31u));
    }
} // namespace KittyAsm

namespace KittyArm32
{
    inline int32_t signExtend(uint32_t val, int bits)
    {
        if (bits <= 0 || bits >= 64)
            return (int32_t)val;

        uint32_t m = 1ULL << (bits - 1);
        return (int32_t)((val ^ m) - m);
    }

    inline std::string regName(unsigned r)
    {
        if (r == 13)
            return "sp";
        if (r == 14)
            return "lr";
        if (r == 15)
            return "pc";

        std::string reg = "r";
        return reg + std::to_string(r);
    }

    inline std::string branchCondName(uint32_t cond)
    {
        static const char *names[16] = {"EQ", "NE", "CS/HS", "CC/LO", "MI", "PL", "VS", "VC",
                                        "HI", "LS", "GE",    "LT",    "GT", "LE", "AL", "NV"};
        uint32_t index = cond & 0xF;
        return index < 16 ? names[index] : "";
    }

    EKittyInsnTypeArm32 decodeInsnType(uint32_t instr);

    KittyInsnArm32 decodeInsn(uint32_t instr, uint32_t address = 0);

    std::string typeToString(EKittyInsnTypeArm32 t);
} // namespace KittyArm32

namespace KittyArm64
{
    inline int64_t signExtend(uint32_t val, int bits)
    {
        if (bits <= 0 || bits >= 64)
            return (int64_t)val;

        uint64_t m = 1ULL << (bits - 1);
        return (int64_t)((val ^ m) - m);
    }

    inline std::string xRegName(unsigned reg, bool isRn)
    {
        if (reg == 31)
        {
            return isRn ? "SP" : "XZR";
        }
        return std::string("X") + std::to_string(reg);
    }

    inline std::string wRegName(unsigned reg, bool isRn)
    {
        if (reg == 31)
        {
            return isRn ? "SP" : "WZR";
        }
        return std::string("W") + std::to_string(reg);
    }

    inline std::string branchCondName(uint32_t cond)
    {
        static const char *names[16] = {"EQ", "NE", "HS", "LO", "MI", "PL", "VS", "VC",
                                        "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"};
        uint32_t index = cond & 0xF;
        return index < 16 ? names[index] : "";
    }

    EKittyInsnTypeArm64 decodeInsnType(uint32_t instr);

    KittyInsnArm64 decodeInsn(uint32_t instr, uint64_t address = 0);

    std::string typeToString(EKittyInsnTypeArm64 t);
} // namespace KittyArm64