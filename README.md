# BrundleX: AI-Guided Malware Triage & Predictive Trait Studio

![BrundleX Banner](assets/brundlex_readme.png)

> **BrundleX** is an open-source malware analysis and trait-simulation workbench. It integrates binary deobfuscation, genetic trait indexing, intermediate language emulation, and semantic mutations. It predicts and detects evasive malware variants before adversaries deploy them.

---

## Key Capabilities

1. **Layered Deobfuscation (`Binary Refinery`):**
   Automatically peels crypters, scans single-byte and multi-byte XOR keys, strips PE overlays, and carves embedded payloads.
2. **Genetic Trait Attribution (`Binlex`):**
   Disassembles instruction chromosomes, filters out C/C++ runtime noise, and calculates MinHash and TLSH similarity against indexed threat families.
3. **Control Flow & Semantics Verification (`Radare2 / ESIL`):**
   Extracts control-flow graphs (CFG) and emulates CPU registers with ESIL (Evaluable Strings Intermediate Language).
4. **Predictive Trait Simulation (Mutation Engine):**
   Applies semantics-preserving mutations (register substitution, instruction permutation, and peephole replacement) to decryptor blocks. Proves register invariance in ESIL and generates resilient YARA rules with automated `??` wildcards.
5. **Decoupled Single-Page Workspace (`FastAPI + HTMX + Pico.css`):**
   Uses zero custom JavaScript. Provides a responsive analyst interface with dark and light themes, progressive HTMX execution polling, SIEM telemetry cards, live audit logging, and YARA rule downloads.

---

## Genetic Metaphor and Theoretical Foundation

BrundleX uses biological genetics as a model for binary code analysis:

- **Binary Chromosomes**:
  In molecular biology, genes encode proteins. In `binlex`, continuous byte sequences of basic blocks with volatile addresses masked out (`??`) serve as operational chromosomes. They capture immutable functional logic.
- **Genetic Lineage and Familial Drift**:
  Adversaries frequently fork code, use shared builder kits, or reuse decryptor routines. BrundleX uses MinHash Jaccard similarity and TLSH locality-sensitive matching to measure familial kinship across threat strains.
- **Harvester as a Genetic Sequencer**:
  The Harvester pulls unpacked threat specimens from MalwareBazaar. It filters samples through a Shannon entropy gate and saves recurring functional chromosomes in a local database (`data/traits.db`).
- **Mutation Studio as an Evolutionary Chamber**:
  Adversaries recompile and mutate decryptor routines to evade static signatures. The Mutation Studio simulates these code variations using semantic transformations. It verifies behavioral equivalence through Radare2 ESIL emulation.
- **Resilient YARA Synthesis**:
  BrundleX aligns verified mutant sequences, keeps invariant operational opcodes, and wildcards mutable operands. This creates detection rules that detect future malware builds before compile time.

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------------+
|                                    BrundleX UI                                          |
|                 FastAPI (server.py) + HTMX 1.9.10 + Pico.css v2.0.6                     |
+-----------------------------------------------------------------------------------------+
                                      |
                         [PocketFlow DAG Orchestrator]
                                      |
         +---------------+------------+------------+---------------+
         |               |                         |               |
         v               v                         v               v
   [IngestNode]     [PeelNode]             [TraitMatchNode]   [VerifyNode]
    SHA256/1/MD5   Binary Refinery          Binlex Disasm      Radare2 R2Pipe
   Shannon Entropy  XOR / Carving            Genetic SQLite     ESIL Emulation
         |               |                         |               |
         +---------------+------------+------------+---------------+
                                      |
                                      v
                             [Analyst Checkpoints]
                     Approve / Override / Skip Decisions
                                      |
                                      v
                                [ReportNode]
                    OpenAI-Compatible LLM / Heuristic
                                      |
                                      v
                        [Predictive Mutation Studio]
                    Semantic Operators + ESIL Verifier
                                      |
                                      v
                    [Resilient YARA Synthesis & Export]
```

---

## Quick-Start Guide

### Prerequisites
- Linux operating system (Ubuntu, Debian, Fedora, RHEL, or Arch)
- `podman` or `docker` installed and active
- GNU `make` installed

### 1. Configure the Environment
Clone the repository and copy the example environment configuration:
```bash
git clone https://github.com/urk0hx/brundlex.git
cd brundlex
cp .env.example .env
```

Edit `.env` to configure optional API keys:
```bash
# Optional: MalwareBazaar API key for live sample harvesting
MALWAREBAZAAR_API_KEY=your_key_here

# Optional: OpenAI-compatible LLM endpoint (Ollama, LM Studio, vLLM, or NVIDIA)
LLM_API_BASE=http://host.containers.internal:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=llama3:8b
LLM_FALLBACK_MODEL=llama3.2:3b
LLM_TIMEOUT_SECONDS=30
```

### 2. Build the Container Image
Build the container image with `binlex`, `radare2`, `binary-refinery`, and `pocketflow`:
```bash
make build
```

### 3. Start the Workspace
Start the studio container in the background:
```bash
make ui-bg
```

Open a web browser and go to:
```
http://localhost:8501
```

To stop the background workspace:
```bash
make ui-stop
```

To run the server in the foreground:
```bash
make ui
```

---

## Threat Harvester Subsystem

The **Harvester** (`src/harvester/` and `tools/harvest_traits.py`) builds and updates the local genetic threat corpus (`data/traits.db`).

### Harvester Operation Flow
1. **Query and Download**: Queries MalwareBazaar by tag (for example `unpacked`) or signature (for example `Stealc`, `Lumma`, `RedLine`). Supports comma-separated batch queries with automatic SHA-256 deduplication.
2. **In-Memory Streaming**: Streams password-protected ZIP archives directly into RAM with standard password `infected`.
3. **Shannon Entropy Gate**: Calculates Shannon entropy ($H$). Rejects samples with $H > 7.1$ to block encrypted or packed containers.
4. **Genetic Chromosome Indexing**: Extracts basic blocks with `binlex`, removes compiler boilerplate, and writes MinHash and TLSH signatures to SQLite.
5. **Clean Workspace Guarantee**: Wipes temporary directories in `/tmp` immediately after indexing.

### Recommended Threat Corpus Baselines
- **Samples per Family**: Ingest 5 to 15 distinct unpacked samples per family.
- **Total Corpus Size**: Maintain 15 to 50 curated samples (500 to 30,000 indexed traits).
- **High-Confidence Attribution**: Jaccard similarity >= 25% with >= 5 shared traits.
- **Variant Lineage Detection**: Jaccard similarity between 10% and 24%.
- **Entropy Gate**: Keep maximum entropy at <= 7.10. High-entropy samples add noise to the database.

### Harvester Execution

#### In the Web Studio
In the left sidebar under **Genetic Threat DB**, open **Harvester Ingest Settings**:
- Enter family names in **Target Family / Signature** (for example `Stealc, Lumma`).
- Set **Tag Query** (default: `unpacked`).
- Set **Sample Limit** per query (1 to 25).
- Click **Run Ingestion**.

#### In the Command-Line Interface
Run live harvesting through the container:
```bash
# Harvest unpacked Stealc samples from MalwareBazaar
podman run --rm -v $(CURDIR):/app:Z --env-file .env brundlex-agent python3 tools/harvest_traits.py --family Stealc --limit 10

# Ingest samples by tag with a custom entropy threshold
podman run --rm -v $(CURDIR):/app:Z --env-file .env brundlex-agent python3 tools/harvest_traits.py --tag unpacked --max-entropy 6.9 --limit 15
```

---

## Predictive Mutation and Invariance Subsystem

Adversaries recompile and modify decryptor loops to break static signatures. BrundleX generates equivalent variants and proves computational invariance before exporting YARA rules.

### Core Concepts

- **Basic Block**: A sequence of instructions with one entry point and one exit point.
- **Cyclomatic Complexity ($CC$)**: Measures independent control-flow paths ($M = E - N + 2P$).
  - **$CC = 1$ to $3$**: Linear blocks ideal for mutation simulation.
  - **$CC > 6$**: Complex control flow with branching.
- **Entropy Comparison**:
  - `bytes_entropy`: Raw byte entropy.
  - `trait_entropy`: Entropy after wildcarding volatile addresses with `??`.
- **Trivial-Block Filter**: Excludes 1-2 instruction boilerplate blocks (such as `pop rbp; ret`).
- **Semantic Replacements**:
  - Clear register: `xor rcx, rcx` <-> `mov rcx, 0` <-> `sub rcx, rcx`.
  - Increment value: `add rax, 1` <-> `inc rax`.
  - Decrement value: `sub rdx, 1` <-> `dec rdx`.
  - Test value: `test rbx, rbx` <-> `or rbx, rbx`.
- **Register Substitution**: Swaps non-volatile general-purpose registers. Protects stack pointers (`rsp`, `rbp`, `rip`).
- **Instruction Permutation**: Reorders independent instructions. Uses hazard analysis to prevent Read-After-Write (RAW), Write-After-Read (WAR), and Write-After-Write (WAW) hazards.
- **ESIL Invariance Verification**: Executes original and mutant blocks in the Radare2 ESIL virtual machine. Verifies that all output registers match.
- **Resilient YARA Synthesis**: Aligns verified mutant blocks. Replaces changing register opcodes with `??` wildcards and anchors invariant opcodes.

### Mutation Controls
- **Aggression Level (1 to 5)**:
  - **Level 1 (Conservative)**: Applies single peephole replacement or register swap.
  - **Level 2 - 3 (Moderate)**: Combines peephole replacements and instruction permutations.
  - **Level 4 - 5 (Aggressive)**: Applies multi-register reallocations and cascading instruction permutations.
- **Variant Count**: Sets the number of unique mutant variants generated and aligned into the YARA rule.

---

## User Guide: Analyst Walkthrough

### 1. Select Target Binary
- In the left sidebar under **Target Binary Selection**, choose a sample from the **Sample Library** (for example `Stealc Core`, `Lumma Stealer`, or `Redline Stealer`).
- Or select **Custom File Path** to specify a local binary.
- Or use **Upload Local Binary** to upload a file directly into the sandbox.
- The top header displays **SHA-256**, **SHA-1**, and **MD5** hashes. Click **Copy All** to copy all formatted hashes.

### 2. Execute Triage Pipeline
- Select your gate preferences under **Human-in-the-Loop Gates**:
  - `Require Approval: Peeling Gate`
  - `Require Approval: Genetic Attribution Gate`
  - `Require Approval: Radare2 Verification Gate`
- Click **Start Triage**.
- The UI provides immediate status feedback. The button shows a busy indicator. The **Pipeline Status** card turns blue (`IN PROGRESS`). The stepper tracks the active stage (`INGEST` -> `PEEL` -> `TRAIT_MATCH` -> `VERIFY` -> `REPORT`).
- When a gate pauses execution, review the **Audit Log & Dialogue** in the sidebar. Click **Approve & Resume** or **Abort**.
- View complete analysis results in the main tabs:
  - **Triage Report**: Complete executive summary, threat attribution, lineage matches, and capabilities. Includes 1-click **Download Report** (`.md`) and **Copy Report** actions.
  - **Genetic Lineage**: Similarity matches from `data/traits.db` and top candidate decryptor chromosomes with **Send to Studio** buttons.
  - **Disassembly & Verification**: Radare2 disassembly, function lists, control flow graph metadata, and emulated CPU registers.
  - **Mutation Studio**: Interactive mutation generator and YARA rule synthesizer.

### 3. Generate Resilient YARA Rules
- Navigate to the **Mutation Studio** tab.
- Enter assembly instructions or use an extracted decryptor block from triage.
- Adjust the **Aggression Level** slider and **Variant Count**.
- Click **Generate & Verify Invariant Mutations**.
- Verify that variants display `VERIFIED` status in the ESIL verification table.
- Expand **Configure YARA Rule Metadata** to customize rule metadata (Rule Name, Threat Family, Author, Severity, TLP).
- Click **Download <rule_name>.yar** to save the signature.

---

## CLI & Batch Commands

All common tasks use the project `Makefile`:

| Command | Description |
| :--- | :--- |
| `make check` | Run static code analysis and linting (`ruff`). |
| `make fix` | Automatically fix linting and formatting issues. |
| `make test` | Run the complete test suite inside the container. |
| `make test-unit` | Run unit tests (`tests/unit/`). |
| `make test-e2e` | Run integration tests (`tests/e2e/`). |
| `make harvest` | Run the command-line trait harvester. |
| `make clean` | Stop containers and remove temporary files. |

---

## Security and Containment

BrundleX follows strict containment practices:
- **Rootless Container**: All analysis executes inside an isolated container.
- **Network Isolation**: Disassembly, payload peeling, and ESIL emulation execute with network access disabled.
- **Ephemeral Storage**: All unzipped files and peeled layers in `/tmp` are removed immediately after processing.

---

## Credits and Dependencies

- **[binlex](https://github.com/c3rb3ru5d3d53c/binlex)**: Created and maintained by **[@c3rb3ru5d3d53c](https://github.com/c3rb3ru5d3d53c)**. Foundational binary genetics lexer used for trait extraction, MinHash hashing, and chromosome generation.
- **[Radare2](https://github.com/radareorg/radare2)**: Reverse engineering framework providing ESIL emulation and control-flow analysis.
- **[Binary Refinery](https://github.com/binref/refinery)**: Created by Jesko Huettenhain (@uhu01). Provides payload deobfuscation and transformation utilities.
- **[PocketFlow](https://github.com/thewh1teagle/pocketflow)**: Minimalist framework for DAG workflows.
- **[MalwareBazaar](https://bazaar.abuse.ch/)**: Abuse.ch community malware exchange providing malware samples and signatures.

---

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
