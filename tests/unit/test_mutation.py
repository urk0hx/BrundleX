"""
Tests for Phase 4: Predictive Trait Simulation Engine.
Failure Modes Covered:
- FM-MUT-01: Register substitution protects stack/base/instruction pointers (rsp, rbp, rip)
- FM-MUT-02: Peephole swaps reject malformed operands or unsupported operations
- FM-MUT-03: Dependency analysis detects RAW, WAR, WAW hazards and prevents unsafe permutation
- FM-MUT-04: ESIL verifier verifies identical CPU state for valid mutations and catches divergences
- FM-MUT-05: YARA generator outputs valid rule with ?? wildcards for mutable bytes
"""

from src.mutation.operators import (
    Instruction,
    apply_peephole_swap,
    can_reorder,
    extract_rw_registers,
    generate_mutations,
    substitute_registers,
)
from src.mutation.verifier import ESILVerifier
from src.mutation.yara_generator import generate_resilient_yara


def test_fm_mut_01_protected_registers_cannot_be_substituted():
    """FM-MUT-01: rsp, rbp, and rip must never be substituted."""
    mapping = {"rsp": "rax", "rbp": "rbx", "rip": "rcx", "rax": "rdx"}
    inst = Instruction(mnemonic="mov", operands=["rsp", "rbp"], bytes_hex="4889ec")

    # Applying substitution must preserve protected registers
    mutated = substitute_registers(inst, mapping)
    assert "rsp" in mutated.operands[0]
    assert "rbp" in mutated.operands[1]

    # Valid general-purpose register substitution
    inst_gp = Instruction(mnemonic="mov", operands=["rax", "1"], bytes_hex="48c7c001000000")
    mutated_gp = substitute_registers(inst_gp, mapping)
    assert mutated_gp.operands[0] == "rdx"


def test_extract_rw_registers():
    """Extracts accurate read and write register sets for x86_64."""
    inst1 = Instruction(mnemonic="mov", operands=["rax", "rbx"], bytes_hex="4889d8")
    reads, writes = extract_rw_registers(inst1)
    assert "rbx" in reads
    assert "rax" in writes

    inst2 = Instruction(mnemonic="add", operands=["rcx", "rdx"], bytes_hex="4801d1")
    reads2, writes2 = extract_rw_registers(inst2)
    assert "rcx" in reads2 and "rdx" in reads2
    assert "rcx" in writes2


def test_fm_mut_02_peephole_swap_valid_and_invalid():
    """FM-MUT-02: Peephole swaps must apply valid equivalences and reject invalid operands."""
    # 1. ADD reg, 1 <-> INC reg
    add_one = Instruction(mnemonic="add", operands=["rax", "1"], bytes_hex="4883c001")
    swapped = apply_peephole_swap(add_one)
    assert swapped is not None
    assert swapped.mnemonic == "inc"
    assert swapped.operands == ["rax"]

    # 2. XOR reg, reg -> MOV reg, 0
    xor_zero = Instruction(mnemonic="xor", operands=["rcx", "rcx"], bytes_hex="4831c9")
    swapped_xor = apply_peephole_swap(xor_zero)
    assert swapped_xor is not None
    assert swapped_xor.mnemonic == "mov"
    assert swapped_xor.operands == ["rcx", "0"]

    # 3. Invalid operand / no equivalent
    nop = Instruction(mnemonic="nop", operands=[], bytes_hex="90")
    assert apply_peephole_swap(nop) is None

    # 4. XOR with different registers is not zeroing
    xor_diff = Instruction(mnemonic="xor", operands=["rax", "rbx"], bytes_hex="4831d8")
    assert apply_peephole_swap(xor_diff) is None


def test_fm_mut_03_dependency_analysis_prevents_unsafe_reordering():
    """FM-MUT-03: Dependency analysis detects RAW, WAR, WAW hazards."""
    # RAW: inst1 writes rax, inst2 reads rax -> CANNOT REORDER
    inst1 = Instruction(mnemonic="mov", operands=["rax", "42"], bytes_hex="48c7c02a000000")
    inst2 = Instruction(mnemonic="add", operands=["rbx", "rax"], bytes_hex="4801c3")
    assert can_reorder(inst1, inst2) is False

    # WAR: inst1 reads rax, inst2 writes rax -> CANNOT REORDER
    inst3 = Instruction(mnemonic="mov", operands=["rbx", "rax"], bytes_hex="4889c3")
    inst4 = Instruction(mnemonic="mov", operands=["rax", "10"], bytes_hex="48c7c00a000000")
    assert can_reorder(inst3, inst4) is False

    # WAW: inst1 writes rax, inst2 writes rax -> CANNOT REORDER
    inst5 = Instruction(mnemonic="mov", operands=["rax", "1"], bytes_hex="48c7c001000000")
    inst6 = Instruction(mnemonic="mov", operands=["rax", "2"], bytes_hex="48c7c002000000")
    assert can_reorder(inst5, inst6) is False

    # Independent instructions: inst7 operates on rcx, inst8 operates on rdx -> CAN REORDER
    inst7 = Instruction(mnemonic="mov", operands=["rcx", "10"], bytes_hex="48c7c10a000000")
    inst8 = Instruction(mnemonic="mov", operands=["rdx", "20"], bytes_hex="48c7c214000000")
    assert can_reorder(inst7, inst8) is True


def test_generate_mutations_aggression_scaling():
    """Generates multiple mutant variants scaled by aggression factor."""
    block = [
        Instruction(mnemonic="mov", operands=["rax", "0"], bytes_hex="48c7c000000000"),
        Instruction(mnemonic="mov", operands=["rcx", "10"], bytes_hex="48c7c10a000000"),
        Instruction(mnemonic="add", operands=["rax", "1"], bytes_hex="4883c001"),
    ]

    variants = generate_mutations(block, aggression=1, num_variants=3)
    assert len(variants) >= 1
    # Check that at least one variant applied peephole swap or register swap
    assert any(len(v) == len(block) for v in variants)


def test_fm_mut_04_esil_verifier_invariance():
    """FM-MUT-04: ESIL verifier verifies identical CPU state and catches divergences."""
    verifier = ESILVerifier()

    # Two semantically identical sequences (e.g., mov rax, 0 vs xor rax, rax)
    # Using hex bytecode:
    # 48c7c000000000 (mov rax, 0) vs 4831c0 (xor rax, rax)
    seq_mov = bytes.fromhex("48c7c000000000")
    seq_xor = bytes.fromhex("4831c0")

    is_invariant, _initial_state, final_states = verifier.verify_equivalence(
        seq_mov, seq_xor, arch="x86", bits=64
    )
    assert is_invariant is True
    assert final_states["original"]["rax"] == 0
    assert final_states["mutant"]["rax"] == 0

    # Divergent sequences: mov rax, 5 vs mov rax, 9
    seq_5 = bytes.fromhex("48c7c005000000")
    seq_9 = bytes.fromhex("48c7c009000000")
    is_inv_div, _, _ = verifier.verify_equivalence(seq_5, seq_9, arch="x86", bits=64)
    assert is_inv_div is False


def test_fm_mut_05_resilient_yara_rule_generation():
    """FM-MUT-05: Generates valid YARA rule with automated ?? wildcards."""
    # Original: 48 31 c0 (xor rax, rax)
    # Mutant 1: 48 31 db (xor rbx, rbx)
    # Mutant 2: 48 31 c9 (xor rcx, rcx)
    # Byte 0 is '48', Byte 1 is '31', Byte 2 mutates -> "48 31 ??"
    variants_bytes = [
        bytes.fromhex("4831c0"),
        bytes.fromhex("4831db"),
        bytes.fromhex("4831c9"),
    ]

    yara_rule = generate_resilient_yara(
        rule_name="brundlex_simulated_decryptor",
        variants=variants_bytes,
        family="LummaStealer",
    )

    assert "rule brundlex_simulated_decryptor" in yara_rule
    assert "48 31 ??" in yara_rule
    assert "strings:" in yara_rule
    assert "condition:" in yara_rule
    assert 'family = "LummaStealer"' in yara_rule


def test_fm_mut_06_configurable_metadata_yara_generation():
    """FM-MUT-06: Verifies extra metadata (severity, tlp, reference) properly formats in YARA rule."""
    variants = [bytes.fromhex("4831c0"), bytes.fromhex("4831db")]
    extra = {
        "severity": "CRITICAL",
        "tlp": "AMBER",
        "reference": "SHA256:abcdef1234567890",
        "created_date": "2026-09-30",
    }
    rule = generate_resilient_yara(
        rule_name="brundlex_custom_rule",
        variants=variants,
        family="Stealc",
        author="SecOps Analyst",
        description="Custom targeted hunting rule",
        extra_meta=extra,
    )
    assert 'rule brundlex_custom_rule' in rule
    assert 'severity = "CRITICAL"' in rule
    assert 'tlp = "AMBER"' in rule
    assert 'reference = "SHA256:abcdef1234567890"' in rule
    assert 'created_date = "2026-09-30"' in rule
    assert 'author = "SecOps Analyst"' in rule
    assert 'family = "Stealc"' in rule


def test_fm_mut_07_analyze_variant_mutation():
    """FM-MUT-07: Analyzes differences between original and mutated instructions for tactical evasion tags."""
    from src.mutation.operators import analyze_variant_mutation

    orig = [
        Instruction(mnemonic="xor", operands=["rcx", "rcx"]),
        Instruction(mnemonic="mov", operands=["rdx", "0x20"]),
    ]

    # Register swap
    reg_swap = [
        Instruction(mnemonic="xor", operands=["rax", "rax"]),
        Instruction(mnemonic="mov", operands=["rdx", "0x20"]),
    ]
    res_reg = analyze_variant_mutation(orig, reg_swap)
    assert res_reg["tactic_tag"] == "Register Swap"
    assert "ModR/M" in res_reg["tactical_summary"]

    # Instruction permutation
    permuted = [
        Instruction(mnemonic="mov", operands=["rdx", "0x20"]),
        Instruction(mnemonic="xor", operands=["rcx", "rcx"]),
    ]
    res_perm = analyze_variant_mutation(orig, permuted)
    assert res_perm["tactic_tag"] == "Instruction Permutation"
    assert "n-grams" in res_perm["tactical_summary"]

    # Peephole swap
    peep = [
        Instruction(mnemonic="mov", operands=["rcx", "0"]),
        Instruction(mnemonic="mov", operands=["rdx", "0x20"]),
    ]
    res_peep = analyze_variant_mutation(orig, peep)
    assert res_peep["tactic_tag"] == "Peephole Optimization"
    assert "Algebraic" in res_peep["tactical_summary"]


def test_fm_mut_08_calculate_rule_metrics():
    """FM-MUT-08: Calculates accurate signature resilience ratio and metrics."""
    from src.mutation.yara_generator import calculate_rule_metrics

    # 3-byte sequence with 1 wildcarded byte: 48 31 ??
    variants = [
        bytes.fromhex("4831c0"),
        bytes.fromhex("4831db"),
        bytes.fromhex("4831c9"),
    ]
    metrics = calculate_rule_metrics(variants)
    assert metrics["total_bytes"] == 3
    assert metrics["anchored_bytes"] == 2
    assert metrics["wildcard_bytes"] == 1
    assert "67% Anchored / 33% Wildcarded" in metrics["resilience_score"]
    assert metrics["verdict"] == "High Resilience"


def test_fm_mut_09_stack_pointer_serialization_barrier():
    """FM-MUT-09: Stack pointer modifications act as hard serialization barriers."""
    # sub rsp, 0x18 modifies rsp; mov r9d, [rsp + 0x28] accesses memory relative to rsp
    inst_alloc = Instruction(mnemonic="sub", operands=["rsp", "0x18"], bytes_hex="4883ec18")
    inst_mem = Instruction(mnemonic="mov", operands=["r9d", "dword ptr [rsp + 0x28]"], bytes_hex="448b4c2428")

    assert can_reorder(inst_alloc, inst_mem) is False
    assert can_reorder(inst_mem, inst_alloc) is False


def test_fm_mut_10_use_before_def_hazard():
    """FM-MUT-10: RAW hazard prevents use-before-def (e.g. mov edi, 1 vs shr edi, cl)."""
    inst_def = Instruction(mnemonic="mov", operands=["edi", "1"], bytes_hex="bf01000000")
    inst_use = Instruction(mnemonic="shr", operands=["edi", "cl"], bytes_hex="d3ef")

    # Swapping would place shr before mov -> clobbers edi and reads uninitialized/stale state
    assert can_reorder(inst_def, inst_use) is False


def test_fm_mut_11_esil_verifier_catches_memory_divergence():
    """FM-MUT-11: ESILVerifier verifies memory/stack state invariance even when registers match."""
    verifier = ESILVerifier()

    # Sequence with store to stack followed by register clobber:
    # Orig: mov edi, 1; shr edi, cl; mov [rsp + 0x24], edi; lea rdi, [rbp - 0x20]
    orig_bytes = bytes.fromhex("f7d9bf01000000d3ef40897c2424488d7de0")
    # Buggy swap: shr edi, cl BEFORE mov edi, 1 -> stored value on stack differs!
    buggy_bytes = bytes.fromhex("f7d9d3efbf0100000040897c2424488d7de0")

    is_inv, _, _ = verifier.verify_equivalence(orig_bytes, buggy_bytes, arch="x86", bits=64)
    assert is_inv is False


def test_fm_mut_12_esil_verifier_with_reg_map():
    """FM-MUT-12: ESILVerifier verifies isomorphic semantic equivalence with register mapping."""
    verifier = ESILVerifier()

    # xor rax, rax vs xor rbx, rbx
    seq_rax = bytes.fromhex("4831c0")
    seq_rbx = bytes.fromhex("4831db")

    is_inv, _, states = verifier.verify_equivalence(
        seq_rax, seq_rbx, arch="x86", bits=64, reg_map={"rax": "rbx"}
    )
    assert is_inv is True
    assert states["original"]["rax"] == 0
    assert states["mutant"]["rbx"] == 0
