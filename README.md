# Titt-På-Ting Backend

API to help developers prioritize which security issues to fix first. Fetches vulnerability data from Nais, enriches with external data, and returns prioritized results.
The API uses the preferred_username claim of a valid bearer token to fetch vulnerability data for the user's teams. 
User Role is set depending on how the user is linked to one or more namespaces.

## Project Structure

```
src/main/kotlin/no/nav/tpt/
├── domain/                                    # Core business logic and interfaces
│   ├── risk/                                  # Risk scoring algorithms and factor calculations
│   │   └── factors/                           # Individual risk factor calculators (EPSS, KEV, build age, etc.)
│   ├── user/                                  # User context and role management interfaces
│   └── vulnerability/                         # Vulnerability domain models and repository interface
├── infrastructure/                            # External integrations and technical implementations
│   ├── auth/                                  # Token introspection and authentication
│   ├── cisa/                                  # CISA KEV catalog integration (PostgreSQL-backed)
│   ├── config/                                # Application configuration
│   ├── database/                              # Database factory and connection management
│   ├── epss/                                  # EPSS API client with circuit breaker and PostgreSQL cache
│   ├── github/                                # GitHub repository metadata storage and queries
│   ├── kafka/                                 # Kafka consumer for GitHub repository events
│   ├── nais/                                  # Nais GraphQL API client for vulnerability data
│   ├── nvd/                                   # NVD database sync service and CVE data management
│   ├── teamkatalogen/                         # Team membership data from Teamkatalogen API
│   ├── user/                                  # User role determination based on team membership
│   ├── vulnerability/                         # Vulnerability data layer implementations
│   └── vulns/                                 # Vulnerability aggregation and enrichment service
├── plugins/                                   # Ktor plugins and application lifecycle
│   ├── Authentication.kt                      # JWT authentication configuration
│   ├── Dependencies.kt                        # Dependency injection setup
│   ├── Kafka.kt                               # Kafka consumer lifecycle management
│   ├── LeaderElection.kt                      # Kubernetes leader election for distributed tasks
│   ├── NvdSync.kt                             # Scheduled NVD synchronization orchestration
│   └── VulnerabilityDataSync.kt               # Scheduled vulnerability data sync (leader-elected)
├── routes/                                    # HTTP API endpoints
│   ├── ConfigRoutes.kt                        # Risk factor documentation endpoint
│   ├── HealthRoutes.kt                        # Liveness and readiness probes
│   ├── ResponseHelpers.kt                     # RFC 9457 Problem Details error responses
│   ├── VulnRoutes.kt                          # Vulnerability query endpoints
│   └── VulnerabilitySearchRoutes.kt           # Vulnerability search and SLA endpoints
└── Application.kt                             # Application entry point

src/main/resources/
├── db/migration/                              # Flyway database migrations
├── graphql/                                   # GraphQL queries for Nais API
├── logback.xml                                # Logging configuration
└── openapi.yaml                               # OpenAPI specification

src/test/                                      # Test suite mirroring main structure
```

## Prerequisites
- Java 25
- Gradle 9.x
- Docker (for testcontainers & building production image)

## Environment Variables

### Required
- `NAIS_TOKEN_INTROSPECTION_ENDPOINT` - Token introspection endpoint
- `NAIS_API_URL` - Nais GraphQL API endpoint
- `NAIS_API_TOKEN` - Nais API token
- `NAIS_DATABASE_TPT_BACKEND_TPT_JDBC_URL` - PostgreSQL JDBC URL (auto-injected by Nais)
- `TEAMKATALOGEN_URL` - Teamkatalogen API URL

### Optional
- `NVD_API_URL` - NVD API URL (default: https://services.nvd.nist.gov/rest/json/cves/2.0)
- `NVD_API_KEY` - NVD API key for higher rate limits
- `EPSS_API_URL` - EPSS API URL (default: https://api.first.org/data/v1)
- `ELECTOR_GET_URL` - Kubernetes leader election URL (auto-injected by Nais)
- `KAFKA_BROKERS` - Kafka broker addresses (auto-injected by Nais)
- `KAFKA_TOPICS` - Comma-separated list of topics to consume
- `KAFKA_*` - Additional Kafka SSL configuration (auto-injected by Nais)

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

Tests use mocked dependencies and testcontainers for PostgreSQL & Kafka.

## Data Sources

- **Nais API** - Vulnerability data and application metadata (scheduled sync to PostgreSQL every 6 hours)
- **NVD** - National Vulnerability Database (PostgreSQL-backed, syncs every 2 hours)
- **CISA KEV** - Known Exploited Vulnerabilities catalog (PostgreSQL-backed, 24h staleness check)
- **EPSS** - Exploit Prediction Scoring System (PostgreSQL-backed with circuit breaker, 24h staleness check)
- **Kafka** - Receives JSON data from other applications (optional)

Initial NVD sync takes ~1-2 hours on first deployment. Vulnerability data sync takes ~10-15 minutes per run.

### Data Persistence Strategy

All external data sources are cached in PostgreSQL with staleness tracking:

**Vulnerability Tracking:**
- Synced every 6 hours from Nais API (leader-elected, configurable)
- **Two-table structure** for efficiency:
  - `cves` - CVE reference data (stored once per CVE)
  - `workload_vulnerabilities` - Tracks which workloads are affected (with JOINs)
- Tracks `discovered_at` and `last_seen_at` timestamps for SLA calculations
- Automatic cleanup of stale data (deleted apps/teams) and orphaned CVEs
- Supports search by team, CVE, severity, ingress type

**Other Data Sources:**
- **EPSS scores**: Refreshed after 24 hours, circuit breaker protects against rate limits (3 failures = 5min cooldown)
- **KEV catalog**: Refreshed after 24 hours, returns stale data if API fails
- **NVD CVE data**: Incremental sync every 2 hours using `lastModifiedDate` tracking

## API Endpoints
Full API documentation available at `/swagger` or see `src/main/resources/openapi.yaml`

## Authentication

Endpoints require a valid JWT Bearer token with:
- `preferred_username` claim for email

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Contact

For any questions, issues, or feature requests, please reach out to the AppSec team:
- Internal: Either our slack channel [#appsec](https://nav-it.slack.com/archives/C06P91VN27M) or contact a [team member](https://teamkatalogen.nav.no/team/02ed767d-ce01-49b5-9350-ee4c984fd78f) directly via slack/teams/mail.
- External: [Open GitHub Issue](https://github.com/navikt/appsec-guide/issues/new/choose)

## Code generated by GitHub Copilot

This project was developed with the assistance of GitHub Copilot, an AI-powered code completion tool.