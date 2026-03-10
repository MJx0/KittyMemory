#pragma once

#include <cstdint>
#include <string>

/**
 * @brief Enumerates ARM32 instruction types.
 */
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

/**
 * @brief Struct representing an ARM32 instruction.
 *
 * This struct contains the details of an ARM32 instruction, including its type,
 * registers, immediate value, target address, and condition.
 */
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

    /**
     * @brief Checks if the instruction is valid.
     */
    inline bool isValid() const
    {
        return bytes != 0 && type != EKittyInsnTypeArm32::UNKNOWN;
    }
};

/**
 * @brief Enumerates ARM64 instruction types.
 */
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

/**
 * @brief Struct representing an ARM64 instruction.
 *
 * This struct contains the details of an ARM64 instruction, including its type,
 * registers, immediate value, target address, and bit position.
 */
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

    /**
     * @brief Checks if the instruction is valid.
     */
    inline bool isValid() const
    {
        return bytes != 0 && type != EKittyInsnTypeArm64::UNKNOWN;
    }
};

/**
 * @brief Namespace containing utility functions for asm instructions.
 *
 * This namespace provides utility functions for decoding instructions,
 */
namespace KittyAsm
{
    /**
     * @brief Extracts a bit value from a 32-bit unsigned integer.
     *
     * @param v The input 32-bit unsigned integer.
     * @param hi The high bit position (inclusive).
     * @param lo The low bit position (inclusive).
     * @return The extracted bit value.
     */
    uint32_t bits(uint32_t v, int hi, int lo);

    /**
     * @brief Checks if a specific bit is set in a 32-bit unsigned integer.
     *
     * @param v The input 32-bit unsigned integer.
     * @param pos The bit position to check.
     * @return true if the bit is set, false otherwise.
     */
    inline bool bit(uint32_t v, int pos)
    {
        return bits(v, pos, pos) != 0;
    }

    /**
     * @brief Rotates a 32-bit unsigned integer to the right by a specified amount.
     *
     * @param value The input 32-bit unsigned integer.
     * @param shift The number of bits to rotate.
     * @return The rotated 32-bit unsigned integer.
     */
    inline uint32_t ror32(uint32_t value, unsigned int shift)
    {
        shift &= 31u;
        return (value >> shift) | (value << ((32 - shift) & 31u));
    }
} // namespace KittyAsm

/**
 * @brief Namespace containing utility functions for ARM32 instructions.
 *
 * This namespace provides utility functions for decoding ARM32 instructions,
 */
namespace KittyArm32
{
    /**
     * @brief Sign-extends a 32-bit unsigned integer to a 32-bit signed integer.
     *
     * @param val The input 32-bit unsigned integer.
     * @param bits The number of bits to sign-extend.
     * @return The sign-extended 32-bit signed integer.
     */
    inline int32_t signExtend(uint32_t val, int bits)
    {
        if (bits <= 0 || bits >= 64)
            return (int32_t)val;

        uint32_t m = 1ULL << (bits - 1);
        return (int32_t)((val ^ m) - m);
    }

    /**
     * @brief Returns the name of an ARM32 general-purpose register.
     *
     * @param r The register number (0-15).
     * @return The name of the register as a string.
     */
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

    /**
     * @brief Returns the name of a conditional execution flag.
     *
     * @param cond The conditional execution flag value (0-15).
     * @return The name of the conditional execution flag as a string.
     */
    inline std::string branchCondName(uint32_t cond)
    {
        static const char *names[16] =
            {"EQ", "NE", "CS/HS", "CC/LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"};
        uint32_t index = cond & 0xF;
        return index < 16 ? names[index] : "";
    }

    /**
     * @brief Decodes type of an ARM32 instruction.
     *
     * @param instr The 32-bit instruction value.
     * @return The type of the instruction.
     */
    EKittyInsnTypeArm32 decodeInsnType(uint32_t instr);

    /**
     * @brief Decodes an ARM32 instruction.
     *
     * @param instr The 32-bit instruction value.
     * @param address The address of the instruction (optional).
     * @return The details of the decoded instruction.
     */
    KittyInsnArm32 decodeInsn(uint32_t instr, uint32_t address = 0);

    /**
     * @brief Converts an EKittyInsnTypeArm32 to a string representation.
     *
     * @param t The instruction type to convert.
     * @return The string representation of the instruction type.
     */
    std::string typeToString(EKittyInsnTypeArm32 t);
} // namespace KittyArm32


/**
 * @brief Namespace containing utility functions for ARM64 instructions.
 *
 * This namespace provides utility functions for decoding ARM64 instructions,
 */
namespace KittyArm64
{
    /**
     * @brief Sign-extends a 32-bit unsigned integer to a 64-bit signed integer.
     *
     * @param val The input 32-bit unsigned integer.
     * @param bits The number of bits to sign-extend.
     * @return The sign-extended 64-bit signed integer.
     */
    inline int64_t signExtend(uint32_t val, int bits)
    {
        if (bits <= 0 || bits >= 64)
            return (int64_t)val;

        uint64_t m = 1ULL << (bits - 1);
        return (int64_t)((val ^ m) - m);
    }

    /**
     * @brief Returns the name of an ARM64 general-purpose X-register.
     */
    inline std::string xRegName(unsigned reg, bool isRn)
    {
        if (reg == 31)
        {
            return isRn ? "SP" : "XZR";
        }
        return std::string("X") + std::to_string(reg);
    }

    /**
     * @brief Returns the name of an ARM64 general-purpose W-register.
     */
    inline std::string wRegName(unsigned reg, bool isRn)
    {
        if (reg == 31)
        {
            return isRn ? "SP" : "WZR";
        }
        return std::string("W") + std::to_string(reg);
    }

    /**
     * @brief Returns the name of a conditional execution flag.
     *
     * @param cond The conditional execution flag value (0-15).
     * @return The name of the conditional execution flag as a string.
     */
    inline std::string branchCondName(uint32_t cond)
    {
        static const char *names[16] =
            {"EQ", "NE", "HS", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"};
        uint32_t index = cond & 0xF;
        return index < 16 ? names[index] : "";
    }

    /**
     * @brief Decodes type of an ARM64 instruction.
     *
     * @param instr The 64-bit instruction value.
     * @return The type of the instruction.
     */
    EKittyInsnTypeArm64 decodeInsnType(uint32_t instr);

    /**
     * @brief Decodes an ARM64 instruction.
     *
     * @param instr The 64-bit instruction value.
     * @param address The address of the instruction (optional).
     * @return The details of the decoded instruction.
     */
    KittyInsnArm64 decodeInsn(uint32_t instr, uint64_t address = 0);

    /**
     * @brief Converts an EKittyInsnTypeArm64 to a string representation.
     *
     * @param t The instruction type to convert.
     * @return The string representation of the instruction type.
     */
    std::string typeToString(EKittyInsnTypeArm64 t);
} // namespace KittyArm64