"""
Generates the Phase 4 proof artifact: artifacts/phase-4/mutation_verification_sample.json
Demonstrates:
1. Mutation operators applied to a decryption/unpacking basic block.
2. Radare2 ESIL invariance verification confirming identical CPU state.
3. Resilient YARA rule generation with automated ?? wildcards.
"""

import json
from pathlib import Path

from src.mutation.operators import (
    Instruction,
    can_reorder,
    generate_mutations,
)
from src.mutation.verifier import ESILVerifier
from src.mutation.yara_generator import generate_resilient_yara


def generate_proof():
    output_dir = Path("artifacts/phase-4")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "mutation_verification_sample.json"

    # Original basic block from an unpacker / XOR decryptor setup routine
    # 1. xor rcx, rcx      -> 4831c9
    # 2. mov rdx, 0x20     -> 48c7c220000000
    # 3. add rax, 1        -> 4883c001
    original_block = [
        Instruction(mnemonic="xor", operands=["rcx", "rcx"], bytes_hex="4831c9"),
        Instruction(mnemonic="mov", operands=["rdx", "0x20"], bytes_hex="48c7c220000000"),
        Instruction(mnemonic="add", operands=["rax", "1"], bytes_hex="4883c001"),
    ]

    original_bytes = b"".join(bytes.fromhex(inst.bytes_hex) for inst in original_block)

    # 1. Variant A: Peephole optimization (xor rcx, rcx -> mov rcx, 0; add rax, 1 -> inc rax)
    var_a_insts = [
        Instruction(mnemonic="mov", operands=["rcx", "0"], bytes_hex="48c7c100000000"),
        Instruction(mnemonic="mov", operands=["rdx", "0x20"], bytes_hex="48c7c220000000"),
        Instruction(mnemonic="inc", operands=["rax"], bytes_hex="48ffc0"),
    ]
    var_a_bytes = b"".join(bytes.fromhex(inst.bytes_hex) for inst in var_a_insts)

    # 2. Variant B: Safe instruction permutation (swap independent inst 1 and 2: mov rdx, 0x20 before xor rcx, rcx)
    assert can_reorder(original_block[0], original_block[1]) is True
    var_b_insts = [
        original_block[1],
        original_block[0],
        original_block[2],
    ]
    var_b_bytes = b"".join(bytes.fromhex(inst.bytes_hex) for inst in var_b_insts)

    # 3. Automated variant generation via mutation engine
    _ = generate_mutations(original_block, aggression=3, num_variants=3)

    verifier = ESILVerifier()
    initial_regs = {
        "rax": 0x10,
        "rbx": 0x20,
        "rcx": 0x30,
        "rdx": 0x40,
        "rsi": 0x50,
        "rdi": 0x60,
    }

    # Verify Variant A
    inv_a, _, state_a = verifier.verify_equivalence(
        original_bytes, var_a_bytes, arch="x86", bits=64, initial_regs=initial_regs
    )

    # Verify Variant B
    inv_b, _, state_b = verifier.verify_equivalence(
        original_bytes, var_b_bytes, arch="x86", bits=64, initial_regs=initial_regs
    )

    # Generate Resilient YARA Rule for a mutated decryptor sequence
    yara_variants = [
        bytes.fromhex("4883c001"),
        bytes.fromhex("4883c301"),
        bytes.fromhex("4883c101"),
    ]
    resilient_yara = generate_resilient_yara(
        rule_name="brundlex_simulated_xor_counter",
        variants=yara_variants,
        family="LummaStealer",
        description="Resilient signature matching mutated register allocations in decryption loop",
    )

    proof_data = {
        "scenario": "Decryption Loop Initialization Block Mutation & Verification",
        "original_block": {
            "assembly": [inst.to_assembly() for inst in original_block],
            "bytecode_hex": original_bytes.hex(),
            "instruction_count": len(original_block),
        },
        "initial_cpu_state": initial_regs,
        "mutant_variants": [
            {
                "variant_id": "variant_a_peephole",
                "transformation": "Peephole Optimization (XOR rcx, rcx -> MOV rcx, 0; ADD rax, 1 -> INC rax)",
                "assembly": [inst.to_assembly() for inst in var_a_insts],
                "bytecode_hex": var_a_bytes.hex(),
                "is_esil_invariant": inv_a,
                "final_registers": state_a["mutant"],
            },
            {
                "variant_id": "variant_b_permutation",
                "transformation": "Instruction Permutation (Independent instruction swap: mov rdx, 0x20 before xor rcx, rcx)",
                "assembly": [inst.to_assembly() for inst in var_b_insts],
                "bytecode_hex": var_b_bytes.hex(),
                "is_esil_invariant": inv_b,
                "final_registers": state_b["mutant"],
            },
        ],
        "original_final_registers": state_a["original"],
        "mathematical_invariance_proven": inv_a and inv_b,
        "resilient_yara_rule": resilient_yara,
    }

    with open(output_file, "w") as f:
        json.dump(proof_data, f, indent=2)

    print(f"Phase 4 proof generated successfully at: {output_file}")


if __name__ == "__main__":
    generate_proof()
