# Titt-På-Ting Backend

API to help developers prioritize which security issues to fix first. Fetches vulnerability data from NAIS, enriches with external data, and returns prioritized results.

## Project Structure

```
src/main/kotlin/no/nav/tpt/
├── domain/                     # Core business logic and interfaces
│   ├── risk/                   # Risk scoring algorithms and factor calculations
│   │   └── factors/            # Individual risk factor calculators (EPSS, KEV, build age, etc.)
│   └── user/                   # User context and role management interfaces
├── infrastructure/             # External integrations and technical implementations
│   ├── auth/                   # Token introspection and authentication
│   ├── cache/                  # Valkey cache implementation
│   ├── cisa/                   # CISA KEV catalog integration
│   ├── config/                 # Application configuration
│   ├── database/               # Database factory and connection management
│   ├── epss/                   # EPSS API client and exploit prediction scores
│   ├── github/                 # GitHub repository metadata storage and queries
│   ├── kafka/                  # Kafka consumer for GitHub repository events
│   ├── nais/                   # NAIS GraphQL API client for vulnerability data
│   ├── nvd/                    # NVD database sync service and CVE data management
│   ├── purl/                   # Package URL (PURL) parsing utilities
│   ├── teamkatalogen/          # Team membership data from Teamkatalogen API
│   ├── user/                   # User role determination based on team membership
│   └── vulns/                  # Vulnerability aggregation and enrichment service
├── plugins/                    # Ktor plugins and application lifecycle
│   ├── Authentication.kt       # JWT authentication configuration
│   ├── Dependencies.kt         # Dependency injection setup
│   ├── Kafka.kt                # Kafka consumer lifecycle management
│   ├── LeaderElection.kt       # Kubernetes leader election for distributed tasks
│   └── NvdSync.kt              # Scheduled NVD synchronization orchestration
├── routes/                     # HTTP API endpoints
│   ├── ConfigRoutes.kt         # Risk factor documentation endpoint
│   ├── HealthRoutes.kt         # Liveness and readiness probes
│   ├── ResponseHelpers.kt      # RFC 9457 Problem Details error responses
│   └── VulnRoutes.kt           # Vulnerability query endpoints
└── Application.kt              # Application entry point

src/main/resources/
├── db/migration/               # Flyway database migrations
├── graphql/                    # GraphQL queries for NAIS API
├── logback.xml                 # Logging configuration
└── openapi.yaml                # OpenAPI specification

src/test/                       # Test suite mirroring main structure
```

## Prerequisites
- Java 25
- Gradle 9.x
- Docker (for Valkey cache and postgresql in tests)

## Environment Variables

- `NAIS_TOKEN_INTROSPECTION_ENDPOINT` - Token introspection endpoint (required)
- `NAIS_API_URL` - NAIS GraphQL API endpoint (required)
- `NAIS_API_TOKEN` - NAIS API token (required)
- `NAIS_DATABASE_TPT_BACKEND_TPT_JDBC_URL` - PostgreSQL JDBC URL (auto-injected by NAIS)
- `NVD_API_URL` - NVD API URL, no default but currently https://services.nvd.nist.gov/rest/json/cves/2.0
- `NVD_API_KEY` - NVD API key for higher rate limits (optional)
- `EPSS_API_URL` - EPSS API URL, no default but currently https://api.first.org/data/v1
- `VALKEY_HOST` - Valkey host (default: localhost)
- `VALKEY_PORT` - Valkey port (default: 6379)
- `VALKEY_USERNAME` - Valkey username (optional)
- `VALKEY_PASSWORD` - Valkey password (optional)
- `CACHE_TTL_MINUTES` - Cache TTL in minutes (default: 60)
- `KAFKA_BROKERS` - Kafka broker addresses (optional, auto-injected by NAIS)
- `KAFKA_TOPICS` - Comma-separated list of topics to consume (optional)
- `KAFKA_*` - Additional Kafka SSL configuration (auto-injected by NAIS)

Request NVD Api key at [NIST](https://nvd.nist.gov/developers/request-an-api-key) and subscribe to [NVD Technical Updates](https://www.nist.gov/itl/nvd).

## Running Locally

```bash
./gradlew runLocalDev
```

Application starts on `http://localhost:8080`

## Testing

```bash
./gradlew test
```

Tests use mocked dependencies and testcontainers for Valkey and PostgreSQL.

## Data Sources

- **NAIS API** - Vulnerability data and application metadata
- **NVD** - National Vulnerability Database (PostgreSQL-backed, syncs every 2 hours)
- **CISA KEV** - Known Exploited Vulnerabilities catalog (Valkey-cached)
- **EPSS** - Exploit Prediction Scoring System (Valkey-cached)
- **Kafka** - Receives JSON data from other applications (optional)

Initial NVD sync takes ~1-2 hours on first deployment.

For detailed Kafka integration documentation, see [KAFKA_INTEGRATION.md](docs/KAFKA_INTEGRATION.md).

## API Endpoints

API documentation available at `/swagger` once the application is running.

## Authentication

Endpoints require a valid JWT Bearer token with:
- `NAVident` claim for user identification
- `preferred_username` claim for email


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Contact

For any questions, issues, or feature requests, please reach out to the AppSec team:
- Internal: Either our slack channel [#appsec](https://nav-it.slack.com/archives/C06P91VN27M) or contact a [team member](https://teamkatalogen.nav.no/team/02ed767d-ce01-49b5-9350-ee4c984fd78f) directly via slack/teams/mail.
- External: [Open GitHub Issue](https://github.com/navikt/appsec-guide/issues/new/choose)

## Code generated by GitHub Copilot

This project was developed with the assistance of GitHub Copilot, an AI-powered code completion tool.