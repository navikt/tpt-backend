---
applyTo: "**/*.test.{kt,kts}"
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
