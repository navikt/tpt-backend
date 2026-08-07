---
applyTo: "src/**/*.kt"
---

# Architecture & Tech Stack

## Project Overview

TittPåTing automatically identifies the user and available resources using OIDC and fetches vulnerability
metadata from a wide range of sources. It calculates a risk score (0–100 additive point model) for each
vulnerability and returns a prioritized list to the user.

**Risk scoring**: 5 weighted categories — Severity (0–25), Exploitation Evidence (0–30), Exposure (0–25),
Environment (0–15), Actionability (0–10). Suppressed vulnerabilities score ×0.2.
Priority buckets: CRITICAL ≥75, HIGH ≥50, MEDIUM ≥25, LOW <25.

The project runs both locally for development/testing and in a serverless environment (GCP) for production.
Docker images use distroless bases. Prefer testcontainers over mocking where practical.

## Integrations

- **Nais API GraphQL**: Fetch vulnerability data and application ingresses
- **Entra ID**: Fetch username from access token claim
- **GCVE (db.gcve.eu)**: Single enrichment source for all CVE metadata — KEV status, EPSS scores, SSVC,
  CVSS, exploit/patch references, ransomware campaign signal, affected products. Replaces standalone
  CISA KEV and EPSS integrations.

## Key Architectural Principles

- **Clean Architecture**: Dependencies point inward (infrastructure → usecase → domain)
- **Dependency Injection**: Ktor lambda-based DI
- **Single Responsibility**: Each class has one clear purpose
- **Interface Segregation**: Small, focused interfaces

## Technology Stack

### Core

- **Framework**: Ktor (Netty engine)
- **Language**: Kotlin (JVM target, Java 25)
- **Serialization**: kotlinx.serialization
- **Testing**: kotlin.test with Ktor test framework, Testcontainers for integration tests

### Infrastructure

- **Database**: PostgreSQL 17 with Exposed ORM and HikariCP connection pooling
- **Migrations**: Flyway for schema versioning
- **Cache**: Valkey (Redis-compatible) for API response caching
- **Leader Election**: Kubernetes native leader election for distributed sync operations
- **Deployment**: GCP Cloud Run with NAIS platform

## Configuration

- **Build Config**: `build.gradle.kts` with version catalogs (`libs.versions.toml`)
- **Environment Variables**: For secrets and deployment-specific values
- **Stable dependencies**: Stick to the latest stable release of all dependencies
