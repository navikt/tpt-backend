---
applyTo: "src/test/**/*.kt"
---

# Testing Conventions

## Test Structure

- **Location**: `src/test/kotlin/` mirroring main structure
- **Naming**: `ClassNameTest.kt` for test classes
- **Test Method Naming**: Backtick syntax with descriptive names using spaces (e.g., `` fun `should generate valid PNG when given valid request`() ``)
- **Framework**: kotlin.test with Ktor test framework
- **Pattern**: Descriptive sentences that clearly explain the behavior being tested

## Test Categories

- **Unit Tests**: Individual class testing with mocks
- **Integration Tests**: Full application context (`testApplication`)
- **API Tests**: End-to-end endpoint testing

## Time and Timestamp Assertions

- Use fixed ISO 8601 timestamps, normally at whole-second precision, for persistence and lifecycle fixtures.
  Derive later syncs, deployments, and cutoffs from the same fixed instant instead of separate `now()` calls.
- Assert exact equality for supplied timestamps that the database can represent. This also applies to
  timestamps nested in data classes, lists, and maps.
- Do not compare live-clock timestamps by truncating both sides to milliseconds, seconds, or minutes.
  Java and Kotlin instants support nanoseconds; PostgreSQL stores microseconds and can round into the
  next millisecond or second. Truncation can therefore still fail at a boundary.
- For timestamps generated inside the code under test, use an injected fixed clock where supported;
  otherwise assert a bounded time range with an explicit allowance for database precision.
- Keep the full date and timezone. Do not compare only `HH:mm` or `mm:ss`, which can hide incorrect dates.
- Use subsecond fixtures only when that precision is the behavior under test, and account explicitly
  for the storage boundary's rounding. Do not reduce production timestamp precision to fix a test.
- Keep SLA, ordering, and retention boundary tests deterministic with explicit times on each side of
  the boundary; do not add sleeps or broad tolerances to make them pass.

## Test Patterns

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

## Test Naming Conventions

- **Positive Tests**: `should [expected behavior] when [condition]` (e.g., `should generate valid image when given valid input`)
- **Negative Tests**: `should [error behavior] when [invalid condition]` (e.g., `should reject request when preset is invalid`)
- **Feature Tests**: `should [feature behavior] for [specific case]` (e.g., `should produce larger images for presentation preset`)
- **Validation Tests**: `should validate [rule] and [expected result]` (e.g., `should validate input and return error details`)
