---
applyTo: "src/main/**/*.kt"
---

# API Design

## OpenAPI Spec

- **Location**: `src/main/resources/openapi.yaml`
- **Always keep the spec in sync** with code changes. When adding, removing, or modifying routes, request/response fields, or status codes, update `openapi.yaml` in the same PR/commit.
- This is especially critical when editing route handlers directly (e.g., `VulnerabilityRoutes.kt`, `GitHubVulnerabilityRoutes.kt`, `AdminRoutes.kt`).

## RESTful Conventions

- **Endpoints**: Descriptive nouns (`/snap` for image generation)
- **HTTP Methods**: POST for resource creation, GET for retrieval
- **Status Codes**: Proper HTTP semantics (200, 400, 500, etc.)

## Request/Response Structure

- **Consistent Naming**: camelCase for JSON fields
- **Optional Parameters**: Nullable with sensible defaults
- **Backward Compatibility**: Deprecated fields maintained with warnings
- **Extensibility**: Preset system for common configurations
