# Agent Instructions & Operating Standards

## 1. Core Engineering Philosophies
- **Test-First Order:** NEVER write unit or component tests after implementation code.
- **E2E Over Unit Testing:** Prioritize end-to-end tests inside the runtime container as the primary verification mechanism. Every E2E test must produce a repeatable, verifiable artifact in `./artifacts/`.
- **Failure-Mode Specification:** When an isolated subsystem or module must be tested independently:
  1. First document all potential failure modes (malformed inputs, timeouts, partial writes, edge cases).
  2. Implement tests asserting those failure conditions.
  3. Only then write the implementation code to satisfy them.
- **Preserve Working Code:** Never modify, reformat, or refactor working code outside the immediate scope of the current task, even if you spot alternative patterns or stylistic improvements.

---

## 2. Environment & Execution
- **Host Isolation:** The host system is strictly for editing text. Never execute project runtimes, compilers, package managers, or language binaries directly on the host machine.
- **Podman Containers:** All builds, linters, databases, and test runs execute inside Podman containers.
- **Makefile as the Interface:** All workflows must run through `make <target>`.
  - **Dual Audience:** Targets must be intuitive for end-users and contributors (`install`, `dev`, `test`, `clean`), not just internal agent shorthands.
  - **Extensibility:** You may introduce new targets for recurring multi-step workflows or developer conveniences. Do not create one-off wrapper targets for trivial single commands or transient debugging.
  - **Core Lifecycles:**
    - `make preflight` : Verifies environment readiness (Podman engine, socket availability, port collisions, presence and integrity of `.env`).
    - `make up` / `make down` : Starts or stops the containerized development environment.
    - `make check` : Runs static analysis, linting, and type checking inside the container.
    - `make test-e2e` : Executes end-to-end scenarios and dumps verification artifacts into `./artifacts/`.

---

## 3. Configuration & Environment Variables
- **`.env.example` as Source of Truth:** All configurable paths, ports, API endpoints, and keys must be documented in `.env.example` with clear comments and safe placeholder values.
- **Zero-Touch `.env`:** Never overwrite, wipe, or commit a user's `.env` file. If a new variable is required, add it to `.env.example` and ask the user to supply or update their local `.env`.
- **Fail Early:** Code must validate required environment variables at startup and fail with clear messaging if any are missing or invalid. Never inject fallback credentials into source code.

---

## 4. Documentation & Phase Tracking
All design, planning, and progress tracking lives inside `./docs/`.

- `docs/design.md`: Core system architecture, contracts, and data models.
- `docs/plan.md`: Roadmap broken into sequential implementation phases.
- `docs/phases/phase-<N>-<slug>.md`: Created or updated during each implementation phase. Each file must document:
  1. **Delivered:** What was completed and tested.
  2. **Proof:** Path to the generated artifact in `./artifacts/` verifying the work.
  3. **Deferred:** Scope items consciously skipped, tech debt incurred, or next steps.
  4. **Human Review Notes:** Points requiring human review or architectural decisions.

Always review `docs/design.md` and `docs/plan.md` before starting work, and keep phase documents updated as work concludes.

Technical writing must adhere to the ASD-STE100 Simplified Technical English standard.

---

## 5. Working Tree & Git Discipline
- **No Automated Commits:** Do not execute `git commit`, `git push`, `git rebase`, or branch alterations unless explicitly instructed.
- **Review-Ready Diffs:** Leave all modifications in the working tree for visual human review. Keep diffs minimal, atomic, and scoped strictly to the task at hand. Avoid formatting sweeps across untouched files.

---

## 6. Circuit Breaker (The Two-Strike Rule)
- If a build, container command, or E2E test fails **twice consecutively**, stop immediately.
- Do not attempt a third automated fix or speculative rewrite.
- Halt execution and report:
  1. The exact command run and the failure output.
  2. The hypothesized root cause explained in clear, plain language without jargon.
  3. The proposed remedy, awaiting explicit human approval before touching any code.
