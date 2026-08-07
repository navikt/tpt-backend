---
applyTo: "**/*.kt"
---

# Kotlin Code Style

## Style Guidelines

- **Line length**: 120 characters max
- **Imports**: Organize with wildcards for 5+ imports from same package
- **Comments**: Inline comments for complex logic only
- **Nullability**: Explicit null handling, prefer safe calls (`?.`)

## File Organization

- One public class per file (private helpers allowed)
- File name matches primary class name
- Package structure reflects architectural layers
- Test files mirror main source structure

## kotlinx.serialization

The shared `Json` config (in `Dependencies.kt`) sets `explicitNulls = false` and `coerceInputValues = true`.
Nullable fields do **not** need a manual `= null` default — the serializer already treats a missing field as
null. Don't reintroduce per-field defaults to work around missing-field errors; fix the shared config instead.
