#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

/**
 * @brief The 4-bit ARM condition field.
 *
 * Identical in meaning on ARM32 and AArch64 - same 16 slots, same encoding -
 * so it is one shared type rather than a per-architecture enum; only the
 * display text differs between the two (ARM32's branchCondName() spells 2/3
 * "CS/HS"/"CC/LO", AArch64's spells them "HS"/"LO"), and that lives in each
 * architecture's own branchCondName(), not in this enum.
 *
 * `None` is not an encoded value - no condition field of any kind reads as
 * 16 - it marks "this instruction is not conditional", the enum's answer to
 * the plain-int fields' -1.
 */
enum class EKittyArmCond : uint8_t
{
    EQ, NE, HS, LO, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL, NV,
    None,
};

/**
 * @brief Enumerates ARM32 instruction types.
 */
enum class EKittyInsnTypeArm32
{
    /// Not decoded. Either a genuinely unmodelled encoding or one this decoder
    /// deliberately declines to guess at; either way nothing may be read off the
    /// other fields.
    UNKNOWN,

    /// `ADD/SUB Rd,PC,#imm` - A32 has no distinct ADR opcode, so both collapse
    /// here, and `target` carries the resolved address with the direction already
    /// applied.
    ADR,

    /// `ADD/SUB Rd,PC,Rm` - the register-operand ADR, and the second half of the
    /// PIC idiom a literal load starts. Its address depends on Rm, so `target`
    /// cannot be computed here; a consumer adds kPcBias to the instruction's own
    /// address and to whatever it knows Rm to be. `subtractsOffset` says which
    /// way it goes, and the two go opposite ways.
    ADR_REG,

    ADD, ///< `ADD Rd,Rn,operand`, PC excluded (that is ADR / ADR_REG).
    SUB, ///< `SUB Rd,Rn,operand`, PC and the SP-prologue form excluded.

    /// `SUB SP,SP,#imm` - stack allocation, one of A32's two function-prologue
    /// idioms alongside PUSH_SP. Split out for the same reason AArch64 splits
    /// SUB_SP_IMM: a consumer looking for function entries should not have to
    /// re-inspect operands to find them.
    SUB_SP_IMM,

    MOV_IMM,     ///< `MOV Rd,#imm` - a materialized constant.
    MOV_REG,     ///< `MOV Rd,Rm` - a genuine register copy, no shift applied.
    /// `MOV Rd,Rm,<shift>` - A32 encodes LSL/LSR/ASR/ROR/RRX as MOV with a
    /// non-zero shift field, so these arrive typed as moves while being shifts.
    /// The result is not Rm's value, and the amount is often a runtime register,
    /// so it is not knowable from the word at all.
    MOV_SHIFTED,

    LDR,  ///< Word load, register or immediate offset.
    STR,  ///< Word store.
    LDRB, ///< Unsigned byte load.
    STRB, ///< Byte store.
    LDRH, ///< Unsigned halfword load.
    STRH, ///< Halfword store.
    LDRSB, ///< Signed byte load.
    LDRSH, ///< Signed halfword load.

    /// `LDR Rd,[PC,#imm]` - the literal-pool load, whose `target` is the pool
    /// slot's address. Rd receives what the slot *contains*, not the slot's own
    /// address.
    LDR_LITERAL,

    /// `LDR Rd,[PC,Rm]` - the register-offset literal load, which both forms
    /// PC+Rm and loads through it in one instruction. Separate from LDR_LITERAL
    /// because its address needs Rm and so cannot be resolved here, and separate
    /// from LDR because its base is the PC rather than a tracked register. Only
    /// the unshifted, adding form is typed this way - a shift or a subtraction
    /// addresses something else entirely.
    LDR_PC_REG,

    B,      ///< Unconditional branch.
    BL,     ///< Branch with link (a call).
    B_COND, ///< Conditional branch; `cond` names the condition.
    BX,     ///< Branch and exchange. BX LR is A32's return idiom.
    /// STMDB SP!,{reglist} (a.k.a. STMFD) - the ARM32 frame-push idiom. Narrowly
    /// recognised (SP-based, write-back store-multiple only), since nothing else
    /// currently needs a general STM decode.
    PUSH_SP,
    /// LDMIA SP!,{reglist} (a.k.a. LDMFD) *with PC in the register list* - the
    /// ARM32 function-return idiom. A pop without PC is a mid-function restore,
    /// not a return, and is deliberately left UNKNOWN rather than guessed at.
    POP_PC,
    /// `MOVW Rd,#imm16` - loads the low half of a 32-bit constant, zeroing the
    /// high half. Paired with MOVT this is how A32 materializes a full address
    /// without a literal pool.
    MOVW,
    /// `MOVT Rd,#imm16` - writes the *high* half and keeps the low one, so it
    /// composes with a preceding MOVW rather than replacing it. The immediate is
    /// reported pre-shifted by 16, ready to OR in.
    MOVT,

    /// Not an instruction: one past the last type, so a test can walk every
    /// value and prove each one is classified by typeToString / isLoad /
    /// isStore / loadStoreWidth. Adding a type above this line and forgetting
    /// one of those is exactly how byte-wide accesses came to be reported as
    /// pointer-width, so the sentinel exists to make that failure loud.
    COUNT,
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

    /// Register indices, always filled. -1 means the field is absent. Names
    /// are produced on demand via regName() rather than stored here, since
    /// nothing else claims the plain field names once no string counterpart
    /// exists to compete for them.
    int rd = -1, rn = -1, rt = -1;
    uint32_t word;    ///< The instruction word itself, as decoded.
    uint32_t address; ///< Where it lives, for PC-relative targets.
    int32_t immediate;
    uint32_t target;
    /// Branch condition for B_COND, resolved on demand via branchCondName();
    /// EKittyArmCond::None for every other type.
    EKittyArmCond cond = EKittyArmCond::None;

    /**
     * @brief The instruction updates its base register (Rn) as a side effect.
     *
     * True for the write-back load/store forms. A consumer that tracks register
     * values must invalidate Rn when it sees this, or it carries on believing a
     * base that the instruction has just moved.
     */
    bool writeback;

    /**
     * @brief The access happens at [Rn]; `immediate` is applied afterwards.
     *
     * Post-indexed forms encode their immediate as a write-back amount, not as an
     * access offset, so a consumer must use 0 as the offset for these.
     */
    bool postIndexed;

    /**
     * @brief The offset is a register (held in `rt`), not `immediate`.
     *
     * Register-offset forms cannot be resolved from the instruction alone, so
     * `immediate` is 0 and a consumer must not treat it as the access offset.
     */
    bool registerOffset;

    /**
     * @brief The second operand / offset register is a *shifted* register.
     *
     * A32 encodes LSL/LSR/ASR/ROR as MOV with a non-zero shift field, so
     * `MOV Rd,Rm,ROR Rs` decodes as type MOV while being a rotate rather than a
     * copy. A consumer that treats this as a plain register move propagates a
     * value the instruction never produced; the shift amount is often a runtime
     * register, so the result is not knowable here at all. Set for the shifted
     * register-offset load/store forms too - `LDR Rd,[Rn,Rm,LSL #2]` addresses
     * Rn + (Rm << 2), which is not Rn + Rm.
     */
    bool shiftedOperand;

    /**
     * @brief The register operand is subtracted rather than added.
     *
     * Two encodings hide this in a bit that is easy to miss, and both mean the
     * result runs the opposite way from the obvious reading: load/store register
     * offsets carry a U bit (`LDR Rd,[Rn,-Rm]`), and the ADR-shaped
     * data-processing forms may be SUB rather than ADD (`SUB Rd,PC,Rm`). The
     * immediate forms fold the sign into `immediate` and `target` already; this
     * is how the register forms report it, since there is nothing to fold it
     * into.
     */
    bool subtractsOffset;

    /**
     * @brief The second operand is a register (held in `rt`), not `immediate`.
     *
     * The data-processing counterpart of `registerOffset`. A32 selects between
     * the two with one encoding bit, and which one is in play decides whether
     * `immediate` or `rt` carries the operand - so a consumer that guesses by
     * testing `rt` for -1 is relying on a convention rather than on what the
     * instruction says.
     */
    bool registerForm;

    /**
     * @brief Rn is PC, so the address is relative to this instruction.
     *
     * True for both the literal forms (`LDR Rd,[PC,#imm]`, whose `target` is
     * computed) and the register-offset form (`LDR Rd,[PC,Rm]`, whose target
     * depends on Rm and so cannot be). A consumer wanting the second form has to
     * add its own PC bias - `address + 8` in A32 - which is why this says which
     * instructions need it rather than leaving callers to test Rn by name.
     */
    bool pcRelative;

    KittyInsnArm32()
        : type(EKittyInsnTypeArm32::UNKNOWN), word(0), address(0), immediate(0), target(0),
          writeback(false), postIndexed(false), registerOffset(false), shiftedOperand(false),
          subtractsOffset(false), registerForm(false), pcRelative(false)
    {
    }

    /**
     * @brief Checks if the instruction is valid.
     */
    inline bool isValid() const
    {
        return word != 0 && type != EKittyInsnTypeArm32::UNKNOWN;
    }

    /**
     * @brief Renders the instruction as a single line of ARM32 assembly text.
     */
    std::string ToString() const;
};

/**
 * @brief Enumerates ARM64 instruction types.
 */
enum class EKittyInsnTypeArm64
{
    /// Not decoded. Either a genuinely unmodelled encoding or one this decoder
    /// declines to guess at; nothing may be read off the other fields.
    UNKNOWN,

    ADR,  ///< `ADR Xd,label` - the complete address, PC-relative, in `target`.
    /// `ADRP Xd,label` - names only the 4 KB *page* the target sits in, so
    /// `target` is page-aligned and a completing ADD or load supplies the rest.
    /// The two are separate types because a consumer must not treat a page as an
    /// address.
    ADRP,

    ADD,  ///< `ADD Xd,Xn,#imm` - the usual completer for an ADRP page.
    SUB,  ///< `SUB Xd,Xn,#imm`, the SP-prologue form excluded.

    MOVZ, ///< `MOVZ Xd,#imm16,LSL #s` - starts a composed immediate, zeroing the rest.
    MOVN, ///< `MOVN Xd,#imm16,LSL #s` - the same, one's-complemented.
    /// `MOVK Xd,#imm16,LSL #s` - *keeps* the other bits, so it ORs into whatever
    /// a preceding MOVZ/MOVN left. A consumer must accumulate rather than replace,
    /// which is what `bComposes` reports downstream.
    MOVK,

    // ── Scaled immediate-offset load/store ────────────────────────────────────
    // The width is carried by the *type*, not by a field, so each width is its
    // own value. Folding any of them together reports the wrong access size, and
    // access size is what separates a pointer field from a counter.

    LDR,   ///< 64-bit load.
    STR,   ///< 64-bit store.
    LDRW,  ///< 32-bit load, zero-extending.
    STRW,  ///< 32-bit store.
    LDRB,  ///< 8-bit load, zero-extending.
    STRB,  ///< 8-bit store.
    LDRH,  ///< 16-bit load, zero-extending.
    STRH,  ///< 16-bit store.
    LDRSB, ///< 8-bit load, sign-extending.
    LDRSH, ///< 16-bit load, sign-extending.
    /// 32-bit load, sign-extending into a 64-bit register. Distinct from LDRW
    /// because the destination is an X register, which is why the two disagree
    /// about the register name to report even though both read 4 bytes.
    LDRSW,

    // ── Pre-indexed (writeback before the access) ─────────────────────────────
    // `[Xn, #imm]!` - the offset is applied to Xn *and* kept. A consumer tracking
    // register values has to invalidate Xn, which `writeback` reports.

    /// 64-bit load, pre-indexed.
    LDR_PRE,
    /// 64-bit store, pre-indexed.
    STR_PRE,
    /// 32-bit pre/post-indexed word forms. They exist for the same reason LDRW
    /// and STRW do: the type is what tells a caller the access width, so folding
    /// them into LDR_PRE/LDR_POST reported every one of them as 8 bytes wide.
    /// 32-bit load, pre-indexed.
    LDRW_PRE,
    /// 32-bit store, pre-indexed.
    STRW_PRE,
    /// 32-bit load, post-indexed.
    LDRW_POST,
    /// 32-bit store, post-indexed.
    STRW_POST,
    /// 8-bit load, pre-indexed.
    LDRB_PRE,
    /// 8-bit store, pre-indexed.
    STRB_PRE,
    /// 16-bit load, pre-indexed.
    LDRH_PRE,
    /// 16-bit store, pre-indexed.
    STRH_PRE,
    /// 8-bit, sign-extending load, pre-indexed.
    LDRSB_PRE,
    /// 16-bit, sign-extending load, pre-indexed.
    LDRSH_PRE,
    /// 32-bit, sign-extending into an x register load, pre-indexed.
    LDRSW_PRE,

    // ── Post-indexed (writeback after the access) ─────────────────────────────
    // `[Xn], #imm` - the access happens at [Xn] and the immediate is applied
    // afterwards, so the immediate is *not* an access offset. Reading it as one
    // places the access at an address the program never formed, which is what
    // `postIndexed` exists to prevent.

    /// 64-bit load, post-indexed.
    LDR_POST,
    /// 64-bit store, post-indexed.
    STR_POST,
    /// 8-bit load, post-indexed.
    LDRB_POST,
    /// 8-bit store, post-indexed.
    STRB_POST,
    /// 16-bit load, post-indexed.
    LDRH_POST,
    /// 16-bit store, post-indexed.
    STRH_POST,
    /// 8-bit, sign-extending load, post-indexed.
    LDRSB_POST,
    /// 16-bit, sign-extending load, post-indexed.
    LDRSH_POST,
    /// 32-bit, sign-extending into an x register load, post-indexed.
    LDRSW_POST,

    // ── Unscaled immediate offset (LDUR / STUR) ───────────────────────────────
    // Same widths again, but the 9-bit offset is signed and *unscaled*, where the
    // LDR/STR forms scale theirs by the access size. Same access, different
    // immediate encoding - which is exactly why they cannot share a type.

    /// 64-bit load, unscaled signed offset.
    LDUR,
    /// 64-bit store, unscaled signed offset.
    STUR,
    /// 32-bit load, unscaled signed offset.
    LDURW,
    /// 32-bit store, unscaled signed offset.
    STURW,
    /// 8-bit load, unscaled signed offset.
    LDURB,
    /// 8-bit store, unscaled signed offset.
    STURB,
    /// 16-bit load, unscaled signed offset.
    LDURH,
    /// 16-bit store, unscaled signed offset.
    STURH,
    /// 8-bit, sign-extending load, unscaled signed offset.
    LDURSB,
    /// 16-bit, sign-extending load, unscaled signed offset.
    LDURSH,
    /// 32-bit, sign-extending into an x register load, unscaled signed offset.
    LDURSW,

    // ── PC-relative literal loads ─────────────────────────────────────────────
    // `LDR Xt,label` - reads the word *stored at* a PC-relative address, so
    // `target` is the slot and the register receives its contents.

    LDR_LITERAL,   ///< 64-bit.
    LDRW_LITERAL,  ///< 32-bit, zero-extending.
    LDRSW_LITERAL, ///< 32-bit, sign-extending into an X register.

    B,      ///< Unconditional branch; also how a tail call reaches its callee.
    BL,     ///< Branch with link - a call, and what the call graph is built from.
    B_COND, ///< Conditional branch; `cond` names the condition.
    CBZ,    ///< Compare-and-branch on zero.
    CBNZ,   ///< Compare-and-branch on non-zero.
    TBZ,    ///< Test-bit-and-branch on zero; `bitpos` carries the bit.
    TBNZ,   ///< Test-bit-and-branch on non-zero.
    /// RET / RETAA / RETAB - unconditional branch to a register, almost always
    /// LR. Without symbols this is the only dependable function terminator, and
    /// the authenticated forms matter in their own right: an arm64e (iOS) build
    /// ends most of its functions with RETAB, so missing them runs every
    /// boundary past its end.
    RET,
    /// STP <Xt1>,<Xt2>, [SP, #-imm]! - pre-indexed store pair with SP as base,
    /// the dominant AArch64 function-prologue idiom. Narrowly recognised: only
    /// the SP-based, pre-indexed form, since nothing downstream needs Rt/Rt2/imm7
    /// for any other STP shape.
    STP_PRE_SP,
    /// SUB SP, SP, #imm - the other function-prologue idiom (plain stack
    /// allocation). A strict subset of the generic SUB encoding, so it must be
    /// checked before it in decodeInsnType.
    SUB_SP_IMM,
    /// MOV Xd, Xm / MOV Wd, Wm - the ORR Xd,XZR,Xm alias, encoded as ORR
    /// (shifted register) with Rn fixed to the zero register. Not modelled by
    /// the base decoder, but compilers routinely copy `this` or a base pointer
    /// into a callee-saved register at function entry, so losing it loses the
    /// value everywhere downstream.
    MOV,

    /// Not an instruction: one past the last type. See the note on
    /// EKittyInsnTypeArm32::COUNT - same purpose, same failure it prevents.
    COUNT,
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

    /// Register indices, always filled. -1 means the field is absent or names
    /// the zero register - which of those two a given type means is not
    /// recoverable from the int alone; see ToString()'s own per-type cases.
    /// Names are produced on demand via xRegName()/wRegName() rather than
    /// stored here, since nothing else claims the plain field names once no
    /// string counterpart exists to compete for them.
    int rd = -1, rn = -1, rt = -1;
    /// Second source-register operand, used by register-register forms like MOV
    /// (Xd = Xm). -1 when not applicable.
    int rm = -1;
    uint32_t word;    ///< The instruction word itself, as decoded.
    uint64_t address; ///< Where it lives, for PC-relative targets.
    int64_t immediate; ///< Decoded immediate, sign-applied. 0 when there is none.
    int64_t bitpos;    ///< Bit position for the bitfield/test forms; -1 when n/a.
    uint64_t target;   ///< Resolved absolute address for the PC-relative forms.
    /// Branch condition for B_COND, resolved on demand via branchCondName();
    /// EKittyArmCond::None for every other type.
    EKittyArmCond cond = EKittyArmCond::None;

    /**
     * @brief The instruction updates its base register (Rn) as a side effect.
     *
     * True for the pre- and post-indexed load/store forms. A consumer that tracks
     * register values must invalidate Rn when it sees this, or it carries on
     * believing a base that the instruction has just moved.
     */
    bool writeback;

    /**
     * @brief The access happens at [Rn]; `immediate` is applied afterwards.
     *
     * The post-indexed forms encode their immediate as a write-back amount, not
     * as an access offset, so a consumer must use 0 as the offset for these.
     */
    bool postIndexed;

    /**
     * @brief The offset is a register (held in `rm`), not `immediate`.
     *
     * Register-offset loads and stores cannot be resolved from the instruction
     * alone, so `immediate` is 0. They are still decoded rather than dropped:
     * a load whose type is unrecognised leaves its destination register holding
     * whatever a consumer previously tracked there, and a stale base is how a
     * confident wrong address gets manufactured.
     */
    bool registerOffset;

    KittyInsnArm64()
        : type(EKittyInsnTypeArm64::UNKNOWN), word(0), address(0), immediate(0), bitpos(0),
          target(0), writeback(false), postIndexed(false), registerOffset(false)
    {
    }

    /**
     * @brief Checks if the instruction is valid.
     */
    inline bool isValid() const
    {
        return word != 0 && type != EKittyInsnTypeArm64::UNKNOWN;
    }

    /**
     * @brief Renders the instruction as a single line of ARM64 assembly text.
     */
    std::string ToString() const;
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
     * @brief Rotates an 8-bit unsigned integer to the right by a specified amount.
     *
     * @param value The input 8-bit unsigned integer.
     * @param shift The number of bits to rotate.
     * @return The rotated 8-bit unsigned integer.
     */
    inline uint8_t ror8(uint8_t value, unsigned int shift)
    {
        shift &= 7u;
        return static_cast<uint8_t>((value >> shift) | (value << ((8 - shift) & 7u)));
    }

    /**
     * @brief Rotates an 8-bit unsigned integer to the left by a specified amount.
     *
     * @param value The input 8-bit unsigned integer.
     * @param shift The number of bits to rotate.
     * @return The rotated 8-bit unsigned integer.
     */
    inline uint8_t rol8(uint8_t value, unsigned int shift)
    {
        shift &= 7u;
        return static_cast<uint8_t>((value << shift) | (value >> ((8 - shift) & 7u)));
    }

    /**
     * @brief Rotates a 16-bit unsigned integer to the right by a specified amount.
     *
     * @param value The input 16-bit unsigned integer.
     * @param shift The number of bits to rotate.
     * @return The rotated 16-bit unsigned integer.
     */
    inline uint16_t ror16(uint16_t value, unsigned int shift)
    {
        shift &= 15u;
        return static_cast<uint16_t>((value >> shift) | (value << ((16 - shift) & 15u)));
    }

    /**
     * @brief Rotates a 16-bit unsigned integer to the left by a specified amount.
     *
     * @param value The input 16-bit unsigned integer.
     * @param shift The number of bits to rotate.
     * @return The rotated 16-bit unsigned integer.
     */
    inline uint16_t rol16(uint16_t value, unsigned int shift)
    {
        shift &= 15u;
        return static_cast<uint16_t>((value << shift) | (value >> ((16 - shift) & 15u)));
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

    /**
     * @brief Rotates a 32-bit unsigned integer to the left by a specified amount.
     *
     * @param value The input 32-bit unsigned integer.
     * @param shift The number of bits to rotate.
     * @return The rotated 32-bit unsigned integer.
     */
    inline uint32_t rol32(uint32_t value, unsigned int shift)
    {
        shift &= 31u;
        return (value << shift) | (value >> ((32 - shift) & 31u));
    }

    /**
     * @brief Rotates a 64-bit unsigned integer to the right by a specified amount.
     *
     * @param value The input 64-bit unsigned integer.
     * @param shift The number of bits to rotate.
     * @return The rotated 64-bit unsigned integer.
     */
    inline uint64_t ror64(uint64_t value, unsigned int shift)
    {
        shift &= 63u;
        return (value >> shift) | (value << ((64 - shift) & 63u));
    }

    /**
     * @brief Rotates a 64-bit unsigned integer to the left by a specified amount.
     *
     * @param value The input 64-bit unsigned integer.
     * @param shift The number of bits to rotate.
     * @return The rotated 64-bit unsigned integer.
     */
    inline uint64_t rol64(uint64_t value, unsigned int shift)
    {
        shift &= 63u;
        return (value << shift) | (value >> ((64 - shift) & 63u));
    }

    /**
     * @brief Reverses the byte order of a 16-bit unsigned integer.
     *
     * @param value The input 16-bit unsigned integer.
     * @return The byte-swapped 16-bit unsigned integer.
     */
    inline uint16_t swap16(uint16_t value)
    {
        return static_cast<uint16_t>((value >> 8) | (value << 8));
    }

    /**
     * @brief Reverses the byte order of a 32-bit unsigned integer.
     *
     * @param value The input 32-bit unsigned integer.
     * @return The byte-swapped 32-bit unsigned integer.
     */
    inline uint32_t swap32(uint32_t value)
    {
        return ((value & 0x000000FFu) << 24) |
               ((value & 0x0000FF00u) << 8)  |
               ((value & 0x00FF0000u) >> 8)  |
               ((value & 0xFF000000u) >> 24);
    }

    /**
     * @brief Reverses the byte order of a 64-bit unsigned integer.
     *
     * @param value The input 64-bit unsigned integer.
     * @return The byte-swapped 64-bit unsigned integer.
     */
    inline uint64_t swap64(uint64_t value)
    {
        return ((value & 0x00000000000000FFull) << 56) |
               ((value & 0x000000000000FF00ull) << 40) |
               ((value & 0x0000000000FF0000ull) << 24) |
               ((value & 0x00000000FF000000ull) << 8)  |
               ((value & 0x000000FF00000000ull) >> 8)  |
               ((value & 0x0000FF0000000000ull) >> 24) |
               ((value & 0x00FF000000000000ull) >> 40) |
               ((value & 0xFF00000000000000ull) >> 56);
    }

    /**
     * @brief Formats a value as a "0x"-prefixed, upper-case hex string.
     *
     * The one place both architectures' ToString() render an address or
     * immediate, so a caller reading disassembly text sees one hex convention
     * rather than whatever each call site happened to write.
     */
    inline std::string toHexString(uint64_t v)
    {
        char Buf[20];
        std::snprintf(Buf, sizeof(Buf), "0x%llX", static_cast<unsigned long long>(v));
        return Buf;
    }
} // namespace KittyAsm

/**
 * @brief Namespace containing utility functions for ARM32 instructions.
 *
 * This namespace provides utility functions for decoding ARM32 instructions,
 */
namespace KittyArm32
{
    // ──── Constants ───────────────────────────────────────────────────────────

    /// A32 instruction size. Fixed at 4 bytes, which is what makes a linear
    /// sweep possible at all - and is exactly the assumption that does not hold
    /// for Thumb/Thumb-2, whose mixed 16/32-bit encoding this decoder does not
    /// handle. The one source of truth for anything stepping through A32 code.
    constexpr uint32_t kInstructionStride = 4;

    /// What A32 reads the PC as: the instruction's own address plus 8, an
    /// artefact of the original three-stage pipeline that the architecture keeps
    /// for compatibility. Every PC-relative form here is biased by it, so the
    /// number lives in one place rather than as a literal 8 at each use.
    constexpr uint32_t kPcBias = 8;

    /// R14, the link register: `BX LR` is how an A32 function returns, so a
    /// consumer looking for returns has to name this register.
    constexpr int kLinkRegister = 14;

    /// ARM32 general-purpose register count: R0-R14. R15 (PC) is deliberately
    /// excluded - every consumer of this constant tracks *live* register state,
    /// and PC's value changes every instruction rather than being something
    /// register-tracking can hold, so it is never a valid array index here. The
    /// one source of truth for register-array sizing and regIndex's bound check.
    constexpr int kNumGPRegisters = 15;

    // ──── Bit helpers ─────────────────────────────────────────────────────────

    /**
     * @brief Sign-extends a 32-bit unsigned integer to a 32-bit signed integer.
     *
     * @param val The input 32-bit unsigned integer.
     * @param bits The number of bits to sign-extend.
     * @return The sign-extended 32-bit signed integer.
     */
    inline int32_t signExtend(uint32_t val, int bits)
    {
        // Guarded against the field's own width, not the ARM64 twin's: `m` is
        // 32-bit here, so a shift landing at bit 32 or above would compute a
        // value the narrowing conversion silently reduces to 0, leaving the
        // out-of-range guard doing nothing to earn its keep.
        if (bits <= 0 || bits >= 32)
            return (int32_t)val;

        uint32_t m = 1u << (bits - 1);
        return (int32_t)((val ^ m) - m);
    }

    // ──── Register naming and indexing ────────────────────────────────────────

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
     * @brief Inverse of regName(): maps a decoded register name back to its index.
     *
     * @param name Register name as produced by regName() - "sp"/"lr"/"pc" for
     *        13/14/15, "r0".."r15" otherwise.
     * @return The register index (0-15), or -1 for anything unrecognised. Note
     *         that 15 (PC) is a valid answer here while being one past
     *         kNumGPRegisters: PC is nameable but not trackable, so a caller
     *         sizing an array by kNumGPRegisters must bound-check the result
     *         rather than index with it directly.
     */
    int regIndex(const std::string &name);

    /**
     * @brief Returns the name of a conditional execution flag.
     *
     * @param cond The conditional execution flag value (0-15).
     * @return The name of the conditional execution flag as a string.
     */
    inline std::string branchCondName(uint32_t cond)
    {
        // Masked, not rejected: the condition is a 4-bit field and callers pass
        // it straight out of the instruction word, so anything above 15 is a
        // caller error rather than a distinct condition. Masking keeps the
        // lookup in range for every possible input.
        static const char *names[16] =
            {"EQ", "NE", "CS/HS", "CC/LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"};
        return names[cond & 0xF];
    }

    // ──── Instruction classification ──────────────────────────────────────────

    /**
     * @brief Converts an EKittyInsnTypeArm32 to a string representation.
     *
     * @param t The instruction type to convert.
     * @return The string representation of the instruction type.
     */
    std::string typeToString(EKittyInsnTypeArm32 t);

    /**
     * @brief Load/Store access width in bytes for an ARM32 instruction type.
     *
     * @param t The instruction type to query.
     * @return 1 for the byte forms, 2 for the halfword forms, 4 for everything
     *         else (word loads/stores, and LDR_LITERAL); 0 for a type that is
     *         not a load or store at all.
     */
    uint8_t loadStoreWidth(EKittyInsnTypeArm32 t);

    /**
     * @brief True when t is one of the load instruction types.
     * @param t The instruction type to query.
     */
    bool isLoad(EKittyInsnTypeArm32 t);

    /**
     * @brief True when t is one of the store instruction types.
     * @param t The instruction type to query.
     */
    bool isStore(EKittyInsnTypeArm32 t);

    // ──── Decoding ────────────────────────────────────────────────────────────

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

} // namespace KittyArm32


/**
 * @brief Namespace containing utility functions for ARM64 instructions.
 *
 * This namespace provides utility functions for decoding ARM64 instructions,
 */
namespace KittyArm64
{
    // ──── Constants ───────────────────────────────────────────────────────────

    /// AArch64 instruction size. Fixed at 4 bytes for every A64 encoding, which
    /// is what lets a linear sweep step without decoding. The one source of truth
    /// for anything stepping through A64 code.
    constexpr uint32_t kInstructionStride = 4;

    /// AArch64 general-purpose register count: X0-X30 plus SP/XZR at index 31.
    /// The one source of truth for register-array sizing and regIndex's bound
    /// check, so the two cannot drift apart.
    constexpr int kNumGPRegisters = 32;

    // ──── Bit helpers ─────────────────────────────────────────────────────────

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

    // ──── Register naming and indexing ────────────────────────────────────────

    /**
     * @brief What register index 31 means in a given instruction field.
     *
     * AArch64 overloads register 31: in most contexts it is the zero register
     * (XZR/WZR, reads as 0 and discards writes), but in the "add/subtract
     * (immediate)" instruction class it is SP in *both* the Rd and Rn fields -
     * there is no "ADD XZR, ..." immediate form. Which one applies is a property
     * of the specific instruction and field being decoded, not of whether the
     * field happens to be the "first" or "second" operand, so it must be passed
     * explicitly by each call site rather than guessed from position.
     */
    enum class EZeroRegOrStackPointer
    {
        ZeroRegister, ///< register 31 denotes XZR/WZR
        StackPointer, ///< register 31 denotes SP
    };

    /**
     * @brief Returns the name of an ARM64 general-purpose X-register.
     */
    inline std::string xRegName(unsigned reg, EZeroRegOrStackPointer at31)
    {
        if (reg == 31)
        {
            return at31 == EZeroRegOrStackPointer::StackPointer ? "SP" : "XZR";
        }
        return std::string("X") + std::to_string(reg);
    }

    /**
     * @brief Returns the name of an ARM64 general-purpose W-register.
     */
    inline std::string wRegName(unsigned reg, EZeroRegOrStackPointer at31)
    {
        if (reg == 31)
        {
            return at31 == EZeroRegOrStackPointer::StackPointer ? "SP" : "WZR";
        }
        return std::string("W") + std::to_string(reg);
    }

    /**
     * @brief Resolves a raw 5-bit encoded register field into a trackable index,
     * without naming it.
     *
     * Not a parse - unlike regIndex(), which recovers an index from a rendered
     * name, this takes the hardware field straight from the instruction word
     * and applies the same register-31 business rule xRegName()/wRegName() use
     * to name it, so `regIndex(xRegName(reg, at31)) == resolveRegIndex(reg,
     * at31)` by construction. That is what the analyzer calls: formatting a
     * 5-bit field as "X3" only to parse it back is most of what a decode used
     * to cost.
     *
     * @return 0-31, or -1 for the zero register, which never holds a base.
     */
    inline int resolveRegIndex(unsigned reg, EZeroRegOrStackPointer at31)
    {
        if (reg == 31)
            return at31 == EZeroRegOrStackPointer::StackPointer ? 31 : -1;
        return static_cast<int>(reg);
    }

    /**
     * @brief Inverse of xRegName()/wRegName(): maps a decoded register name back to its index.
     *
     * @param name Register name as produced by xRegName()/wRegName() - "X0".."X30"/
     *        "W0".."W30", "SP", or "XZR"/"WZR".
     * @return The register index (0-31), or -1 for a name that does not denote a
     *         trackable base - notably XZR/WZR, since the zero register never
     *         holds one.
     */
    int regIndex(const std::string &name);

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

    // ──── Instruction classification ──────────────────────────────────────────

    /**
     * @brief Converts an EKittyInsnTypeArm64 to a string representation.
     *
     * @param t The instruction type to convert.
     * @return The string representation of the instruction type.
     */
    std::string typeToString(EKittyInsnTypeArm64 t);

    /**
     * @brief Load/Store access width in bytes for an AArch64 instruction type.
     *
     * Covers the pre-indexed, post-indexed, unscaled and literal forms as well
     * as the plain ones: the type is the only thing that carries the width, so a
     * form missing from here reports the wrong size rather than no size.
     *
     * Reports 0 for anything that is not a load or store, matching the ARM32
     * twin: width is non-zero exactly for the types isLoad/isStore accept, so
     * a caller never has to check those first to get a trustworthy answer.
     *
     * @param t The instruction type to query.
     * @return 1/2/4/8 for the byte/halfword/word/doubleword forms; 0 for a type
     *         that is not a load or store at all.
     */
    uint8_t loadStoreWidth(EKittyInsnTypeArm64 t);

    /**
     * @brief True when t is one of the load instruction types.
     *
     * Includes the pre-indexed, post-indexed and literal forms. A load missing
     * from here is not merely unrecorded: a consumer that models only what it
     * recognises leaves the destination register holding a stale tracked value.
     *
     * @param t The instruction type to query.
     */
    bool isLoad(EKittyInsnTypeArm64 t);

    /**
     * @brief True when t is one of the store instruction types.
     * @param t The instruction type to query.
     */
    bool isStore(EKittyInsnTypeArm64 t);

    // ──── Decoding ────────────────────────────────────────────────────────────

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

} // namespace KittyArm64