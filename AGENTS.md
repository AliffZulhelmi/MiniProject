# AGENTS — Guidance for AI coding agents

Purpose
- Short, actionable instructions so AI agents become productive immediately.

Quick Commands
- Install dependencies: `pip install -r requirements.txt`
- Run unit tests: `pytest`
- Run the UI dashboard: `streamlit run mini_wids/ui/app.py`

Where to read more
- Project README: [README.md](README.md)
- Project structure: [docs/project-structure.md](docs/project-structure.md)
- Lab and workflow notes: [docs/kali-lab-guide.md](docs/kali-lab-guide.md)

Key areas (high level)
- `mini_wids/engine.py`: orchestration and detector runner
- `mini_wids/capture/`: packet capture and normalization
- `mini_wids/detectors/`: detector implementations (deauth, rogue_ap, etc.)
- `mini_wids/reporting/`: report building
- `mini_wids/storage/`: repository abstraction for persistence
- `mini_wids/ui/`: Streamlit dashboard entry point (`app.py`)

Conventions for agents
- Link, don't embed: link to docs or tests instead of copying large sections.
- Minimal edits: prefer focused, minimal changes and add tests for behavior changes.
- Config is authoritative: `config/*.yml` contains policy and whitelist data — avoid changing without a clear migration and tests.
- Tests live under `tests/` and should be updated when behavior changes.

Code Style
- **KISS:** Keep functions and modules small, obvious, and easy to reason about.
- **DRY:** Avoid duplication by extracting shared behavior into well-named helpers or services.
- **SOLID:** Prefer single-responsibility classes, explicit interfaces, dependency injection, and composition over inheritance where appropriate.
- **Modular:** Organize code into small modules with clear boundaries and minimal public surface area.
- **Formatting & linting:** Use an automatic formatter (`black`) and a linter/fast checker (`flake8` or `ruff`) and include fixable rules in CI.
- **Tests:** Add unit tests for new logic under `tests/` and keep them small and focused.

What agents can do automatically
- Run tests and report failures (`pytest`).
- Create or update small helper files, tests, and documentation.
- Propose, but do not push, changes to `config/` files; ask for human approval.

When in doubt
- Ask for clarification about intent (test, bugfix, feature).
- Link to relevant docs in PR descriptions.

Next suggested agent customizations
- Create a small `skill` for running the test matrix and reporting failures.
- Add a `hook` that checks for accidental edits to `config/*.yml`.
