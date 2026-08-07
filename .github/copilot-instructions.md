# Copilot Instructions for TPT

TittPåTing (TPT) is a Kotlin/Ktor API that identifies a user's resources via OIDC, enriches vulnerability
metadata from external sources, and returns a risk-scored, prioritized list of security issues to fix.

**Build**: Gradle with Kotlin DSL (`build.gradle.kts`, version catalog in `libs.versions.toml`).

## Task discipline (applies to every task)

- Break work into small tasks; verify one step before moving to the next. If in doubt, ask for clarification
  and do not stray beyond the requested scope (e.g. don't add docs or extend functionality unprompted).
- Do NOT add code comments unless the logic is genuinely complex.
- Do NOT add documentation files or explanations unless specifically asked — **except** the root `README.md`,
  which must be kept concise and updated whenever functionality, packages, or folder structure change.
- Do not use `timeout` when running terminal commands (zsh on macOS).
- The user verifies functionality manually; you do not need to build or run the app to confirm your changes.

## Reference

Loaded automatically by Copilot when editing matching files — no need to open manually:

- [Architecture & tech stack](instructions/architecture.instructions.md) — project domain, integrations, layering, infrastructure
- [Kotlin code style](instructions/kotlin-style.instructions.md) — formatting, file organization, nullability
- [Error handling (RFC 9457)](instructions/error-handling.instructions.md) — Problem Details pattern
- [API design](instructions/api-design.instructions.md) — OpenAPI sync, REST conventions
- [Common patterns](instructions/patterns.instructions.md) — use case, factory, leader election
- [Database & sync jobs](instructions/database-kotlin.instructions.md) — repository pattern, transactions, NVD/Vulnrichment sync, performance
- [Kafka integration](instructions/kafka.instructions.md) — optional consumer, SSL config, health-check contract
- [Security](instructions/security.instructions.md) — input validation, error responses, CORS
- [Testing conventions](instructions/testing.instructions.md) — naming, structure, patterns
- [Migration file standards](instructions/database.instructions.md) — Flyway SQL naming and structure
- [GCVE API](instructions/gcve-api.instructions.md) — non-obvious facts about db.gcve.eu
