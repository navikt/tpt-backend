# Copilot Instructions for AppSec Guide

**EXTREMELY IMPORTANT**: 
- Break up changes into smaller tasks and verify functionality before moving on. 
If in doubt, ask for clarification. For example, if asked to implement functionality for fetching a set of data. 
Do not stray outside of this task. Ask if the user wants you to add documentation or extend the functionality
of the initial request.
- Do NOT do add anything comprehensive unless specifically instructed. 
- Do NOT add documentation unless specifically asked.
- Do NOT add comments in code unless the logic is VERY complex. 
- The user will verify functionality manually and ask for changes if needed. No need to build or run the application for verification.
- **DO NOT ADD EXTRA DOCUMENTATION OR EXPLANATIONS UNLESS SPECIFICALLY ASKED.**
- Do not use timeout when running terminal commands, we are running zsh on macos.
- When adding or removing functionality we update the root README.md with relevant information. Keep the information here VERY concise and to the point. For example when adding or removing a package or refactoring existing folder structure.

## Project Overview

AppSec Guide is an api used to help developers prioritize which security issues to fix first. 
The project automatically identifies the user and available resources using OIDC and fetches available metadata
from a wide range of sources. We then use this data to calculate a risk score for each vulnerability and return a prioritized list to the user.

The project must be able to run locally for development and testing, as well as in a serverless environment (gcp) for production use.
The docker images will use distroless images. For testing we will avoid mocking as much as possible and use testcontainers or similar solutions.

### Integrations
- **Nais API GraphQL**: Fetch vulnerability data and application ingresses
- **Entra ID**: Fetch username from access token claim
- **NVD (National Vulnerability Database)**: Complete CVE dataset with CISA KEV data embedded
- **EPSS (Exploit Prediction Scoring System)**: Probability scores for exploit likelihood
- **CISA KEV**: Embedded in NVD data (no separate integration needed)

### Key Architectural Principles
- **Clean Architecture**: Dependencies point inward (infrastructure → usecase → domain)
- **Dependency Injection**: Uses Ktor for lambda-based DI
- **Single Responsibility**: Each class has one clear purpose
- **Interface Segregation**: Small, focused interfaces 

## Technology Stack

### Core Technologies
- **Framework**: Ktor (Netty engine)
- **Language**: Kotlin (JVM target, Java 25)
- **Dependency Injection**: Ktor lambda-based DI
- **Serialization**: kotlinx.serialization
- **Testing**: kotlin.test with Ktor test framework, Testcontainers for integration tests
- **Build**: Gradle with Kotlin DSL

### Infrastructure
- **Database**: PostgreSQL 17 with Exposed ORM and HikariCP connection pooling
- **Migrations**: Flyway for schema versioning
- **Cache**: Valkey (Redis-compatible) for API response caching
- **Leader Election**: Kubernetes native leader election for distributed sync operations
- **Deployment**: GCP Cloud Run with NAIS platform

## Coding Conventions

### Code Style Guidelines
- **Line Length**: 120 characters max
- **Imports**: Organize with wildcards for 5+ imports from same package
- **Documentation**: Inline comments for complex logic only
- **Nullability**: Explicit null handling, prefer safe calls (`?.`)

### File Organization
- **One public class per file** (private helpers allowed)
- **File name matches primary class name**
- **Package structure reflects architectural layers**
- **Test files mirror main source structure**

### Error Handling Patterns
The project adheres to Problem Details RFC9457 for error handling.

Example request:
```
POST /purchase HTTP/1.1
Host: store.example.com
Content-Type: application/json
Accept: application/json, application/problem+json

{
"item": 123456,
"quantity": 2
}
```

Problem details response:
```
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
Content-Language: en

{
 "type": "https://example.com/probs/out-of-credit",
 "title": "You do not have enough credit.",
 "detail": "Your current balance is 30, but that costs 50.",
 "instance": "/account/12345/msgs/abc",
 "balance": 30,
 "accounts": ["/account/12345",
              "/account/67890"]
}
```

```kotlin
// Exception handling with proper logging
try {
    // Business logic
} catch (e: SerializationException) {
    call.respond(HttpStatusCode.BadRequest, ErrorResponse(...))
} catch (e: IOException) {
    call.respond(HttpStatusCode.InternalServerError, ErrorResponse(...))
}
```

## Testing Conventions

### Test Structure
- **Location**: `src/test/kotlin/` mirroring main structure
- **Naming**: `ClassNameTest.kt` for test classes
- **Test Method Naming**: Backtick syntax with descriptive names using spaces (e.g., `fun \`should generate valid PNG when given valid request\`()`)
- **Framework**: kotlin.test with Ktor test framework
- **Pattern**: Descriptive sentences that clearly explain the behavior being tested

### Test Categories
- **Unit Tests**: Individual class testing with mocks
- **Integration Tests**: Full application context (`testApplication`)
- **API Tests**: End-to-end endpoint testing

### Test Patterns
```kotlin
@Test
fun `should generate valid PNG when given valid request`() = testApplication {
    application { module() }
    val response = client.post("/snap") {
        contentType(ContentType.Application.Json)
        setBody(validSnapRequest)
    }
    assertEquals(HttpStatusCode.OK, response.status)
    assertTrue(response.contentType()?.match(ContentType.Image.PNG) == true)
}

@Test
fun `should reject request with invalid preset`() = testApplication {
    application { module() }
    val response = client.post("/snap") {
        contentType(ContentType.Application.Json)
        setBody(invalidPresetRequest)
    }
    assertEquals(HttpStatusCode.BadRequest, response.status)
}
```

### Test Naming Conventions
- **Positive Tests**: `should [expected behavior] when [condition]` (e.g., `should generate valid image when given valid input`)
- **Negative Tests**: `should [error behavior] when [invalid condition]` (e.g., `should reject request when preset is invalid`)
- **Feature Tests**: `should [feature behavior] for [specific case]` (e.g., `should produce larger images for presentation preset`)
- **Validation Tests**: `should validate [rule] and [expected result]` (e.g., `should validate input and return error details`)

## API Design Patterns

### RESTful Conventions
- **Endpoints**: Descriptive nouns (`/snap` for image generation)
- **HTTP Methods**: POST for resource creation, GET for retrieval
- **Status Codes**: Proper HTTP semantics (200, 400, 500, etc.)

### Request/Response Structure
- **Consistent Naming**: camelCase for JSON fields
- **Optional Parameters**: Nullable with sensible defaults
- **Backward Compatibility**: Deprecated fields maintained with warnings
- **Extensibility**: Preset system for common configurations

## Configuration & Environment

### Application Configuration
- **Build Config**: `build.gradle.kts` with version catalogs (`libs.versions.toml`)
- **Environment Variables**: For secrets and deployment-specific values
- **Stable dependencies**: We will stick to the latest stable release of all dependencies.

## Common Patterns & Best Practices

- We follow best practices from the kotlin foundation and ktor documentation.

### Use Case Pattern
```kotlin
class GenerateCodeImageUseCase(
    private val highlighterService: CodeHighlighterService,
    private val rendererFactory: ImageRendererFactory
) {
    suspend fun execute(request: GenerateImageRequest): ByteArray {
        // Business logic here
    }
}
```

### Factory Pattern
```kotlin
class ImageRendererFactory {
    fun createRenderer(designSystem: String): ImageRenderer = when (designSystem) {
        "material" -> MaterialDesignImageRenderer()
        "macos" -> Java2DImageRenderer()
        else -> Java2DImageRenderer() // default
    }
}
```

### Leader Election Pattern
```kotlin
class LeaderElection(private val httpClient: HttpClient) {
    suspend fun isLeader(): Boolean {
        val electorUrl = System.getenv("ELECTOR_PATH") ?: return true // Local dev
        val response = httpClient.get(electorUrl)
        val leaderInfo: LeaderInfo = response.body()
        return hostname == leaderInfo.name
    }
    
    suspend fun <T> ifLeader(operation: suspend () -> T): T? {
        return if (isLeader()) operation() else null
    }
}
```

### Database Transaction Pattern
```kotlin
suspend fun <T> dbQuery(block: suspend () -> T): T =
    newSuspendedTransaction(Dispatchers.IO) { block() }

// Batch operations with chunking
suspend fun upsertCves(cves: List<NvdCveData>) {
    cves.chunked(500).forEach { batch ->
        dbQuery {
            batch.forEach { cve ->
                // Upsert logic
            }
        }
    }
}
```

## Performance Considerations

- **Database Indexes**: Proper indexes on frequently queried fields
- **Connection Pooling**: HikariCP for efficient database connection management
- **Batch Processing**: Chunked operations for large datasets (e.g., 500 CVEs per batch)
- **Rate Limiting**: Respect external API rate limits (NVD: 6 seconds between requests)

## Database Patterns

### Repository Pattern
```kotlin
interface NvdRepository {
    suspend fun getCveData(cveId: String): NvdCveData?
    suspend fun upsertCves(cves: List<NvdCveData>)
    suspend fun getLastModifiedDate(): LocalDateTime?
}
```

### Migration Management
- **Location**: `src/main/resources/db/migration/`
- **Naming**: `V{version}__{description}.sql` (e.g., `V1__create_nvd_tables.sql`)
- **Execution**: Flyway runs migrations automatically on application startup
- **Reversibility**: Avoid destructive changes; use new migrations to modify schema

### NVD Sync Strategy
- **Initial Sync**: Year-by-year from 2002 to present (~1-2 hours, leader-only)
- **Incremental Sync**: Every 2 hours using `lastModifiedDate` tracking (leader-only)
- **Leader Election**: Kubernetes native leader election prevents duplicate syncs
- **Date Format**: ISO 8601 with UTC timezone (`2024-01-01T00:00:00.000Z`)
- **Error Handling**: HTTP status checking before response deserialization

## Security Considerations

- **Input Validation**: All inputs validated before processing
- **Error Information**: No sensitive data in error responses
- **CORS Configuration**: Properly configured for web clients
- **Content Type Validation**: Strict content type checking

## Additional Guidelines

## Code Review Standards
- Check for logic errors, code style, and architectural consistency.
- Ensure all code (including Copilot-generated) is readable, maintainable, and tested.
- Review for security issues, proper error handling, and input validation.
- Require at least one approving review before merging PRs.

## Security Standards
- Follow OWASP Top 10 guidelines for web application security.
- Never commit secrets or sensitive data; use environment variables.
- Regularly update dependencies and review for vulnerabilities.
- Validate all user input and sanitize outputs.
- Use secure defaults for CORS, headers, and authentication.

## CI/CD Best Practices
- All code must pass linting, static analysis, and tests before merge.
- Use conventional commit messages for automated changelog generation.
- Automate releases and Docker builds via GitHub Actions.

## Key File References
- **README.md**: Project overview, setup, and API usage.
- **copilot-instructions.md**: Coding, commit, and workflow standards.
- **.github/workflows/**: CI/CD automation.
- **scripts/**: Automation scripts for testing.

## Documentation Update Workflow
- Update copilot-instructions.md and other docs for any new conventions or major changes.
- Review documentation changes in PRs; require approval before merging.
- Keep documentation concise, actionable, and up-to-date.