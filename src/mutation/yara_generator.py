from typing import Any

"""
Resilient YARA Signature Generator for Predictive Trait Simulation.
Synthesizes resilient detection rules with automated wildcarding (??) over mutable bytes
across generated semantic variants, or multi-variant signature patterns for variable-length mutations.
"""

from collections.abc import Mapping, Sequence


def generate_resilient_yara(
    rule_name: str,
    variants: Sequence[bytes],
    family: str = "Unknown",
    author: str = "BrundleX Agent",
    description: str = "Resilient signature synthesized by BrundleX Predictive Trait Simulation",
    extra_meta: Mapping[str, str] | None = None,
) -> str:
    """
    Synthesizes a resilient YARA rule by computing a differential byte-level mask
    across all provided mutant variants, or emitting multi-variant pattern alternatives
    when variants differ in length or byte alignment.
    Supports additional metadata key-value pairs (e.g., reference, threat_level, tlp, date).
    """
    if not variants:
        raise ValueError("At least one variant bytecode sequence is required to generate a YARA rule.")

    # Sanitize rule name for YARA syntax
    safe_rule_name = "".join(c if c.isalnum() or c == "_" else "_" for c in rule_name)

    same_length = len({len(v) for v in variants}) == 1
    min_len = min(len(v) for v in variants)

    tokens: list[str] = []
    if same_length and min_len > 0:
        for i in range(min_len):
            unique_bytes = {v[i] for v in variants}
            if len(unique_bytes) == 1:
                tokens.append(f"{next(iter(unique_bytes)):02x}")
            else:
                tokens.append("??")

    # A wildcard pattern is effective only if it retains non-wildcard anchor bytes
    # and isn't dominated by 100% wildcards
    wildcard_is_effective = bool(tokens) and any(t != "??" for t in tokens) and (tokens.count("??") / len(tokens) <= 0.6)

    string_lines: list[str] = []
    if wildcard_is_effective:
        pattern_hex = " ".join(tokens)
        string_lines.append(f"        $mutated_pattern = {{ {pattern_hex} }}")
        condition_str = "        $mutated_pattern"
    else:
        # Emit each unique variant bytecode as an invariant pattern alternative
        seen_patterns = set()
        v_idx = 1
        for v in variants:
            if not v:
                continue
            hex_str = " ".join(f"{b:02x}" for b in v)
            if hex_str not in seen_patterns:
                seen_patterns.add(hex_str)
                string_lines.append(f"        $variant_{v_idx} = {{ {hex_str} }}")
                v_idx += 1
        if not string_lines:
            string_lines.append('        $empty = "none"')
            condition_str = "        $empty"
        elif len(string_lines) == 1:
            condition_str = "        $variant_1"
        else:
            condition_str = "        1 of ($variant_*)"

    # Build meta block
    meta_lines = [
        f'        description = "{description}"',
        f'        family = "{family}"',
        f'        author = "{author}"',
    ]

    if extra_meta:
        for k, v in extra_meta.items():
            clean_k = "".join(c if c.isalnum() or c == "_" else "_" for c in str(k)).strip("_")
            if clean_k and clean_k not in ("description", "family", "author"):
                clean_v = str(v).replace('"', '"')
                meta_lines.append(f'        {clean_k} = "{clean_v}"')

    formatted_meta = "\n".join(meta_lines)
    formatted_strings = "\n".join(string_lines)

    yara_template = f"""rule {safe_rule_name} {{
    meta:
{formatted_meta}
    strings:
{formatted_strings}
    condition:
{condition_str}
}}
"""
    return yara_template


def calculate_rule_metrics(variants: Sequence[bytes]) -> dict[str, Any]:
    """
    Computes rule resilience and specificity metrics:
    anchored opcode ratio, wildcard density, and tactical verdict.
    """
    if not variants:
        return {
            "total_bytes": 0,
            "anchored_bytes": 0,
            "wildcard_bytes": 0,
            "anchored_ratio": 0.0,
            "wildcard_ratio": 0.0,
            "resilience_score": "0% Anchored",
            "verdict": "No Variants",
            "explanation": "No byte patterns available for resilience evaluation.",
        }

    same_length = len({len(v) for v in variants}) == 1
    min_len = min(len(v) for v in variants)

    if same_length and min_len > 0:
        anchored = 0
        wildcards = 0
        for i in range(min_len):
            unique_bytes = {v[i] for v in variants}
            if len(unique_bytes) == 1:
                anchored += 1
            else:
                wildcards += 1

        anchored_pct = round((anchored / min_len) * 100)
        wildcard_pct = 100 - anchored_pct

        if anchored_pct >= 60:
            verdict = "High Resilience"
            explanation = "Operational opcodes remain anchored while mutable register indices and constants are generalized with wildcards."
        elif anchored_pct >= 40:
            verdict = "Balanced Resilience"
            explanation = "Broad mutation coverage. Verify specificity against clean baseline binaries to minimize false positive risk."
        else:
            verdict = "Broad / Low Anchor"
            explanation = "High wildcard density. Multiple registers and instructions mutated across variants."

        return {
            "total_bytes": min_len,
            "anchored_bytes": anchored,
            "wildcard_bytes": wildcards,
            "anchored_ratio": round(anchored / min_len, 4),
            "wildcard_ratio": round(wildcards / min_len, 4),
            "resilience_score": f"{anchored_pct}% Anchored / {wildcard_pct}% Wildcarded",
            "verdict": verdict,
            "explanation": explanation,
        }
    else:
        total_unique = len({v for v in variants if v})
        return {
            "total_bytes": sum(len(v) for v in variants),
            "anchored_bytes": sum(len(v) for v in variants),
            "wildcard_bytes": 0,
            "anchored_ratio": 1.0,
            "wildcard_ratio": 0.0,
            "resilience_score": f"{total_unique} Invariant Patterns",
            "verdict": "Multi-Variant Pattern",
            "explanation": "Emits distinct exact byte patterns for variable-length mutations to guarantee zero false wildcards.",
        }
