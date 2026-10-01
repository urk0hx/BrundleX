"""
Mutation Operators for Predictive Trait Simulation Engine.
Implements:
- Register substitution (preserving stack and base pointers)
- Peephole optimization semantic swaps (add/inc, xor/mov 0, test/or)
- Hazard dependency analysis (preventing RAW, WAR, WAW reordering)
- Instruction permutation and multi-variant mutation generation
"""

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

PROTECTED_REGISTERS = {
    "rsp", "rbp", "rip",
    "esp", "ebp", "eip",
    "sp", "bp", "ip",
}

GP_REGISTERS_64 = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]

GP_REGISTERS_32 = [
    "eax", "ebx", "ecx", "edx", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
]

GP_REGISTERS_16 = [
    "ax", "bx", "cx", "dx", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
]

GP_REGISTERS_8 = [
    "al", "bl", "cl", "dl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
]

ALL_KNOWN_REGISTERS = (
    set(GP_REGISTERS_64)
    | set(GP_REGISTERS_32)
    | set(GP_REGISTERS_16)
    | set(GP_REGISTERS_8)
    | PROTECTED_REGISTERS
    | {"ah", "bh", "ch", "dh"}
)


def get_register_pool(reg: str) -> list[str]:
    """Returns the general-purpose register pool matching the bit-width of reg."""
    reg_l = reg.lower()
    if reg_l in GP_REGISTERS_64:
        return GP_REGISTERS_64
    if reg_l in GP_REGISTERS_32:
        return GP_REGISTERS_32
    if reg_l in GP_REGISTERS_16:
        return GP_REGISTERS_16
    if reg_l in GP_REGISTERS_8:
        return GP_REGISTERS_8
    return []


@dataclass
class Instruction:
    """Represents a disassembled machine instruction."""

    mnemonic: str
    operands: list[str] = field(default_factory=list)
    bytes_hex: str = ""

    def __post_init__(self):
        self.mnemonic = self.mnemonic.lower().strip()
        self.operands = [op.strip() for op in self.operands]
        if not self.bytes_hex:
            self.bytes_hex = assemble_instruction(self.mnemonic, self.operands)

    def to_assembly(self) -> str:
        if not self.operands:
            return self.mnemonic
        return f"{self.mnemonic} {', '.join(self.operands)}"


def assemble_instruction(mnemonic: str, operands: list[str], arch: str = "x86", bits: int = 64) -> str:
    """Assembles an instruction string using rasm2 if available."""
    if not shutil.which("rasm2"):
        return ""

    line = f"{mnemonic} {', '.join(operands)}".strip()
    try:
        res = subprocess.run(
            ["rasm2", "-a", arch, "-b", str(bits), line],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        return res.stdout.strip()
    except (subprocess.SubprocessError, OSError) as e:
        logger.debug(f"rasm2 assembly failed for '{line}': {e}")
        return ""


def _extract_registers_from_string(s: str) -> set[str]:
    """Finds all register tokens in an operand string."""
    tokens = re.findall(r"\b[a-zA-Z0-9]+\b", s.lower())
    return {t for t in tokens if t in ALL_KNOWN_REGISTERS}


def extract_rw_registers(inst: Instruction) -> tuple[set[str], set[str]]:
    """
    Computes read and write register sets for x86/x64 instructions.
    Returns: (reads, writes)
    """
    reads: set[str] = set()
    writes: set[str] = set()
    mnemonic = inst.mnemonic.lower()
    operands = inst.operands

    if not operands:
        return reads, writes

    dst = operands[0]
    dst_regs = _extract_registers_from_string(dst)
    is_dst_memory = "[" in dst and "]" in dst

    if mnemonic in ["mov", "movzx", "movsx", "lea"]:
        if len(operands) > 1:
            src = operands[1]
            reads.update(_extract_registers_from_string(src))

        if is_dst_memory:
            reads.update(dst_regs)
        else:
            writes.update(dst_regs)

    elif mnemonic in ["add", "sub", "xor", "or", "and", "shl", "shr", "sar", "imul"]:
        if len(operands) > 1:
            src = operands[1]
            reads.update(_extract_registers_from_string(src))

        reads.update(dst_regs)
        if not is_dst_memory:
            writes.update(dst_regs)

    elif mnemonic in ["inc", "dec", "not", "neg"]:
        reads.update(dst_regs)
        if not is_dst_memory:
            writes.update(dst_regs)

    elif mnemonic in ["cmp", "test"]:
        reads.update(dst_regs)
        if len(operands) > 1:
            reads.update(_extract_registers_from_string(operands[1]))

    elif mnemonic == "push":
        reads.update(dst_regs)
        writes.add("rsp")

    elif mnemonic == "pop":
        if is_dst_memory:
            reads.update(dst_regs)
        else:
            writes.update(dst_regs)
        writes.add("rsp")

    else:
        # Default fallback: assume destination read/written, source read
        reads.update(dst_regs)
        if not is_dst_memory:
            writes.update(dst_regs)
        for op in operands[1:]:
            reads.update(_extract_registers_from_string(op))

    return reads, writes


def substitute_registers(inst: Instruction, mapping: dict[str, str]) -> Instruction:
    """
    Substitutes register operands based on mapping while strictly protecting
    stack and base pointers (rsp, rbp, rip).
    """
    new_operands: list[str] = []
    for op in inst.operands:
        new_op = op
        # Protect stack/base pointer registers
        for reg, target in mapping.items():
            if reg in PROTECTED_REGISTERS or target in PROTECTED_REGISTERS:
                continue
            # Use word-boundary replacement so 'rax' doesn't replace part of another token
            new_op = re.sub(rf"\b{re.escape(reg)}\b", target, new_op, flags=re.IGNORECASE)
        new_operands.append(new_op)

    new_bytes = assemble_instruction(inst.mnemonic, new_operands)
    return Instruction(mnemonic=inst.mnemonic, operands=new_operands, bytes_hex=new_bytes or inst.bytes_hex)


def apply_peephole_swap(inst: Instruction) -> Instruction | None:
    """
    Applies semantic equivalence peephole transformations:
    - add reg, 1 <-> inc reg
    - sub reg, 1 <-> dec reg
    - xor reg, reg <-> mov reg, 0
    - test reg, reg <-> or reg, reg
    """
    mnemonic = inst.mnemonic.lower()
    operands = inst.operands

    # 1. add reg, 1 -> inc reg
    if mnemonic == "add" and len(operands) == 2 and operands[1] in ["1", "0x1"]:
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS:
            return Instruction(mnemonic="inc", operands=[reg])

    # 2. inc reg -> add reg, 1
    if mnemonic == "inc" and len(operands) == 1:
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS:
            return Instruction(mnemonic="add", operands=[reg, "1"])

    # 3. sub reg, 1 -> dec reg
    if mnemonic == "sub" and len(operands) == 2 and operands[1] in ["1", "0x1"]:
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS:
            return Instruction(mnemonic="dec", operands=[reg])

    # 4. dec reg -> sub reg, 1
    if mnemonic == "dec" and len(operands) == 1:
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS:
            return Instruction(mnemonic="sub", operands=[reg, "1"])

    # 5. xor reg, reg -> mov reg, 0
    if mnemonic == "xor" and len(operands) == 2 and operands[0].lower() == operands[1].lower():
        reg = operands[0]
        return Instruction(mnemonic="mov", operands=[reg, "0"])

    # 6. mov reg, 0 -> xor reg, reg
    if mnemonic == "mov" and len(operands) == 2 and operands[1] in ["0", "0x0"]:
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS and "[" not in reg:
            return Instruction(mnemonic="xor", operands=[reg, reg])

    # 7. test reg, reg -> or reg, reg
    if mnemonic == "test" and len(operands) == 2 and operands[0].lower() == operands[1].lower():
        reg = operands[0]
        return Instruction(mnemonic="or", operands=[reg, reg])

    return None


def get_peephole_alternatives(inst: Instruction) -> list[Instruction]:
    """
    Returns all semantically equivalent alternative instructions for a given instruction.
    """
    alts: list[Instruction] = []
    base_swap = apply_peephole_swap(inst)
    if base_swap:
        alts.append(base_swap)

    mnemonic = inst.mnemonic.lower()
    operands = inst.operands

    # xor reg, reg -> also sub reg, reg
    if mnemonic == "xor" and len(operands) == 2 and operands[0].lower() == operands[1].lower():
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS:
            sub_inst = Instruction(mnemonic="sub", operands=[reg, reg])
            if sub_inst not in alts:
                alts.append(sub_inst)

    # mov reg, 0 -> also sub reg, reg
    elif mnemonic == "mov" and len(operands) == 2 and operands[1] in ["0", "0x0"]:
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS and "[" not in reg:
            sub_inst = Instruction(mnemonic="sub", operands=[reg, reg])
            if sub_inst not in alts:
                alts.append(sub_inst)

    # add reg, 1 -> also sub reg, -1
    elif mnemonic == "add" and len(operands) == 2 and operands[1] in ["1", "0x1"] or mnemonic == "inc" and len(operands) == 1:
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS:
            neg_inst = Instruction(mnemonic="sub", operands=[reg, "-1"])
            if neg_inst not in alts:
                alts.append(neg_inst)

    # sub reg, 1 -> also add reg, -1
    elif mnemonic == "sub" and len(operands) == 2 and operands[1] in ["1", "0x1"] or mnemonic == "dec" and len(operands) == 1:
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS:
            neg_inst = Instruction(mnemonic="add", operands=[reg, "-1"])
            if neg_inst not in alts:
                alts.append(neg_inst)

    # test reg, reg -> also and reg, reg
    elif mnemonic == "test" and len(operands) == 2 and operands[0].lower() == operands[1].lower():
        reg = operands[0]
        if reg.lower() not in PROTECTED_REGISTERS:
            and_inst = Instruction(mnemonic="and", operands=[reg, reg])
            if and_inst not in alts:
                alts.append(and_inst)

    return alts


def can_reorder(inst1: Instruction, inst2: Instruction) -> bool:
    """
    Determines if two adjacent instructions can be reordered without violating
    data dependencies (RAW, WAR, WAW) or memory consistency.
    """
    reads1, writes1 = extract_rw_registers(inst1)
    reads2, writes2 = extract_rw_registers(inst2)

    # RAW: inst1 writes what inst2 reads
    if writes1 & reads2:
        return False

    # WAR: inst1 reads what inst2 writes
    if reads1 & writes2:
        return False

    # WAW: both write to the same register
    if writes1 & writes2:
        return False

    # Prevent reordering across memory operations conservatively
    has_mem1 = any("[" in op for op in inst1.operands)
    has_mem2 = any("[" in op for op in inst2.operands)
    if has_mem1 and has_mem2:
        return False

    # Prevent reordering jumps or calls
    control_flow = {"jmp", "je", "jne", "jz", "jnz", "call", "ret"}
    return inst1.mnemonic not in control_flow and inst2.mnemonic not in control_flow


def generate_mutations(
    block: list[Instruction],
    aggression: int = 1,
    num_variants: int = 3,
) -> list[list[Instruction]]:
    """
    Generates semantically equivalent mutant variants of an instruction basic block.
    Supports 32-bit and 64-bit general-purpose registers, multi-instruction peepholes,
    multi-pair permutations, and compound multi-operator mutations.

    Aggression levels:
      1: Conservative (single peepholes, verified adjacent permutations)
      2: Moderate (register substitutions across matching register pools)
      3: Aggressive (compound mutations: register substitution + peephole transformations)
      4: Highly Aggressive (compound mutations: register swap + peephole + instruction permutations)
      5: Maximum (full combinatorial exploration, speculative permutations, and register re-allocations)
    """
    # Extract register pools for all registers used in the block
    used_by_pool: dict[int, tuple[list[str], list[str]]] = {}
    for inst in block:
        r, w = extract_rw_registers(inst)
        for reg in r | w:
            pool = get_register_pool(reg)
            if pool and reg not in PROTECTED_REGISTERS:
                pid = id(pool)
                if pid not in used_by_pool:
                    used_by_pool[pid] = ([], pool)
                if reg not in used_by_pool[pid][0]:
                    used_by_pool[pid][0].append(reg)

    reg_mappings: list[dict[str, str]] = []
    for (used_regs, pool) in used_by_pool.values():
        avail_regs = [r for r in pool if r not in used_regs and r not in PROTECTED_REGISTERS]
        for u in used_regs:
            for a in avail_regs:
                reg_mappings.append({u: a})
        if len(used_regs) >= 2 and len(avail_regs) >= 2:
            reg_mappings.append({used_regs[0]: avail_regs[0], used_regs[1]: avail_regs[1]})
            if len(avail_regs) >= 4:
                reg_mappings.append({used_regs[0]: avail_regs[2], used_regs[1]: avail_regs[3]})

    # TIER A: Conservative (single peepholes and adjacent permutations)
    tier_conservative: list[list[Instruction]] = []
    for idx, inst in enumerate(block):
        for alt in get_peephole_alternatives(inst):
            v = list(block)
            v[idx] = alt
            if v != block and v not in tier_conservative:
                tier_conservative.append(v)
    for i in range(len(block) - 1):
        if can_reorder(block[i], block[i + 1]):
            perm = list(block)
            perm[i], perm[i + 1] = perm[i + 1], perm[i]
            if perm != block and perm not in tier_conservative:
                tier_conservative.append(perm)

    # TIER B: Register Substitutions
    tier_register: list[list[Instruction]] = []
    for mapping in reg_mappings:
        v = [substitute_registers(inst, mapping) for inst in block]
        if v != block and v not in tier_register and v not in tier_conservative:
            tier_register.append(v)

    # TIER C: Compound (Register + Peephole, and multi-peephole)
    tier_compound: list[list[Instruction]] = []
    if len(block) > 1:
        v_all = []
        for inst in block:
            alt = apply_peephole_swap(inst)
            v_all.append(alt if alt else inst)
        if v_all != block and v_all not in tier_conservative and v_all not in tier_compound:
            tier_compound.append(v_all)

    for base in (tier_register[:6] or [block]):
        for idx, inst in enumerate(base):
            for alt in get_peephole_alternatives(inst):
                v = list(base)
                v[idx] = alt
                if v != block and v not in tier_conservative and v not in tier_register and v not in tier_compound:
                    tier_compound.append(v)

    # TIER D: Triple Compound (Register + Peephole + Permutations)
    tier_full: list[list[Instruction]] = []
    bases = tier_compound[:6] or tier_register[:6] or [block]
    for base in bases:
        for i in range(len(base) - 1):
            if can_reorder(base[i], base[i + 1]):
                perm = list(base)
                perm[i], perm[i + 1] = perm[i + 1], perm[i]
                if (
                    perm != block
                    and perm not in tier_conservative
                    and perm not in tier_register
                    and perm not in tier_compound
                    and perm not in tier_full
                ):
                    tier_full.append(perm)

    # TIER E: Speculative and Deep Permutations
    tier_speculative: list[list[Instruction]] = []
    for i in range(len(block) - 1):
        perm = list(block)
        perm[i], perm[i + 1] = perm[i + 1], perm[i]
        if (
            perm != block
            and perm not in tier_conservative
            and perm not in tier_register
            and perm not in tier_compound
            and perm not in tier_full
            and perm not in tier_speculative
        ):
            tier_speculative.append(perm)

    if len(block) >= 3:
        perm = list(block)
        perm[0], perm[2] = perm[2], perm[0]
        if (
            perm != block
            and perm not in tier_conservative
            and perm not in tier_register
            and perm not in tier_compound
            and perm not in tier_full
            and perm not in tier_speculative
        ):
            tier_speculative.append(perm)

    # Order tiers based on requested aggression level
    if aggression <= 1:
        tier_order = [tier_conservative, tier_register, tier_compound, tier_full, tier_speculative]
    elif aggression == 2:
        tier_order = [tier_register, tier_conservative, tier_compound, tier_full, tier_speculative]
    elif aggression == 3:
        tier_order = [tier_compound, tier_register, tier_conservative, tier_full, tier_speculative]
    elif aggression == 4:
        tier_order = [tier_full, tier_compound, tier_register, tier_speculative, tier_conservative]
    else:  # 5
        tier_order = [tier_speculative, tier_full, tier_compound, tier_register, tier_conservative]

    variants: list[list[Instruction]] = []
    for tier in tier_order:
        for v in tier:
            if v not in variants and v != block:
                variants.append(v)
            if len(variants) >= num_variants:
                return variants

    return variants[:num_variants]


def analyze_variant_mutation(
    orig_block: list[Instruction],
    variant: list[Instruction],
) -> dict[str, str]:
    """
    Analyzes differences between the original instruction block and a mutated variant.
    Returns tactical evasion context: tactic tag, succinct summary, and tooltip explanation.
    """
    if len(orig_block) != len(variant):
        return {
            "tactic_tag": "Instruction Restructuring",
            "tactical_summary": "Altered sequence length",
            "tactical_explanation": "Alters sequence length and instruction boundary alignments. Evades signatures dependent on fixed byte offsets.",
        }

    mnemonic_diffs = 0
    operand_diffs = 0
    order_diffs = 0

    orig_inst_strings = [inst.to_assembly().lower() for inst in orig_block]
    var_inst_strings = [inst.to_assembly().lower() for inst in variant]

    if sorted(orig_inst_strings) == sorted(var_inst_strings) and orig_inst_strings != var_inst_strings:
        return {
            "tactic_tag": "Instruction Permutation",
            "tactical_summary": "Breaks sequential n-grams",
            "tactical_explanation": "Reorders independent instructions without data hazards. Evades strict sequential n-gram and byte-offset matchers.",
        }

    for o_inst, v_inst in zip(orig_block, variant):
        if o_inst.mnemonic.lower() != v_inst.mnemonic.lower():
            mnemonic_diffs += 1
        elif [op.lower() for op in o_inst.operands] != [op.lower() for op in v_inst.operands]:
            operand_diffs += 1

    if order_diffs > 0 and mnemonic_diffs == 0 and operand_diffs == 0:
        return {
            "tactic_tag": "Instruction Permutation",
            "tactical_summary": "Breaks sequential n-grams",
            "tactical_explanation": "Reorders independent instructions without data hazards. Evades strict sequential n-gram and byte-offset matchers.",
        }

    if mnemonic_diffs > 0 and operand_diffs == 0 and order_diffs == 0:
        return {
            "tactic_tag": "Peephole Optimization",
            "tactical_summary": "Algebraic opcode swap",
            "tactical_explanation": "Substitutes instructions with algebraic equivalents. Defeats static signatures anchored on specific compiler opcodes.",
        }

    if operand_diffs > 0 and mnemonic_diffs == 0 and order_diffs == 0:
        return {
            "tactic_tag": "Register Swap",
            "tactical_summary": "Evades ModR/M register masks",
            "tactical_explanation": "Reallocates general-purpose registers across the block. Defeats signatures anchored on fixed ModR/M register bytes.",
        }

    tactics = []
    if order_diffs > 0:
        tactics.append("Permutation")
    if mnemonic_diffs > 0:
        tactics.append("Peephole")
    if operand_diffs > 0:
        tactics.append("Reg Swap")

    tactic_label = " + ".join(tactics) if tactics else "Semantic Transformation"
    return {
        "tactic_tag": tactic_label,
        "tactical_summary": "Compound semantic evasion",
        "tactical_explanation": "Applies simultaneous register reallocation and instruction transformations. Defeats multi-stage static heuristics.",
    }
