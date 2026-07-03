package no.nav.tpt.infrastructure.gcve

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.epss.InMemoryCircuitBreaker
import kotlin.test.*

class GcveClientTest {

    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        coerceInputValues = true
    }

    private val mockBaseUrl = "https://test.gcve.eu/api"

    private fun createClient(
        mockEngine: MockEngine,
        apiKey: String? = null,
        circuitBreaker: InMemoryCircuitBreaker = InMemoryCircuitBreaker(failureThreshold = 3, openDurationSeconds = 300)
    ): GcveClient {
        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) { json(json) }
        }
        return GcveClient(httpClient, mockBaseUrl, apiKey, circuitBreaker)
    }

    @Test
    fun `should fetch single vulnerability by CVE ID`() = runTest {
        val mockEngine = MockEngine { request ->
            assertEquals("$mockBaseUrl/vulnerability/CVE-2021-44228", request.url.toString())
            respond(
                content = GcveModelsTest.LOG4J_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-2021-44228")

        assertNotNull(result)
        assertEquals("CVE-2021-44228", result.cveMetadata.cveId)
    }

    @Test
    fun `should return null for 404`() = runTest {
        val mockEngine = MockEngine {
            respond(content = "Not Found", status = HttpStatusCode.NotFound)
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-9999-99999")

        assertNull(result)
    }

    @Test
    fun `should handle empty JSON response gracefully when status is success`() = runTest {
        val mockEngine = MockEngine {
            // GCVE returns {} for CVEs that don't exist but have 200 status
            respond(
                content = """{}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-2026-48758")

        // Should return null instead of throwing JsonConvertException
        assertNull(result)
    }

    @Test
    fun `should handle malformed response JSON gracefully when status is success`() = runTest {
        val mockEngine = MockEngine {
            // Simulate GCVE returning a JSON object without required fields
            respond(
                content = """{"error": "Something went wrong"}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-2026-48758")

        // Should return null instead of throwing JsonConvertException
        assertNull(result)
    }

    @Test
    fun `should handle HTML error response when status is success`() = runTest {
        val mockEngine = MockEngine {
            // Sometimes servers return HTML error pages even with 200 status
            respond(
                content = """<html><body>Temporary error</body></html>""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "text/html")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-2026-48758")

        // Should return null instead of throwing JsonConvertException
        assertNull(result)
    }

    @Test
    fun `should include API key header when provided`() = runTest {
        val mockEngine = MockEngine { request ->
            assertEquals("test-api-key-123", request.headers["X-API-KEY"])
            respond(
                content = GcveModelsTest.LOG4J_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine, apiKey = "test-api-key-123")
        client.getVulnerability("CVE-2021-44228")
    }

    @Test
    fun `should not include API key header when not provided`() = runTest {
        val mockEngine = MockEngine { request ->
            assertNull(request.headers["X-API-KEY"])
            respond(
                content = GcveModelsTest.LOG4J_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        client.getVulnerability("CVE-2021-44228")
    }

    @Test
    fun `should fetch incremental vulnerabilities with since parameter`() = runTest {
        val mockEngine = MockEngine { request ->
            val url = request.url.toString()
            assertTrue(url.contains("vulnerability/"))
            assertTrue(url.contains("since=2026-07-01T00%3A00%3A00") || url.contains("since=2026-07-01T00:00:00"))
            assertTrue(url.contains("per_page=50"))
            assertTrue(url.contains("date_sort=updated"))
            respond(
                content = GcveModelsTest.LIST_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerabilitiesSince("2026-07-01T00:00:00", page = 1)

        assertNotNull(result)
        assertEquals(2, result.size)
    }

    @Test
    fun `should restrict incremental sweep to source=cvelistv5 by default`() = runTest {
        val mockEngine = MockEngine { request ->
            assertEquals("cvelistv5", request.url.parameters["source"])
            respond(
                content = GcveModelsTest.LIST_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        client.getVulnerabilitiesSince("2026-07-01T00:00:00")
    }

    @Test
    fun `should allow overriding the source filter for incremental sweep`() = runTest {
        val mockEngine = MockEngine { request ->
            assertEquals("nvd", request.url.parameters["source"])
            respond(
                content = "[]",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        client.getVulnerabilitiesSince("2026-07-01T00:00:00", source = "nvd")
    }

    @Test
    fun `should skip records with unexpected shape instead of failing the whole page`() = runTest {
        // A CSAF-format security advisory (e.g. csaf_redhat), which some GCVE sources
        // return in the bulk sweep, has a completely different top-level shape
        // (document/product_tree/vulnerabilities) than CVE Record v5 and cannot be
        // deserialized into GcveCveRecord.
        val csafNoiseRecord = """
            {
                "document": {"category": "csaf_security_advisory", "csaf_version": "2.0"},
                "product_tree": {},
                "vulnerabilities": [{"cve": "CVE-2025-61726"}],
                "containers": {}
            }
        """.trimIndent()

        val mockEngine = MockEngine {
            respond(
                content = "[${GcveModelsTest.LOG4J_RESPONSE}, $csafNoiseRecord]",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerabilitiesSince("2026-07-01T00:00:00")

        assertNotNull(result)
        assertEquals(1, result.size)
        assertEquals("CVE-2021-44228", result[0].cveMetadata.cveId)
    }

    @Test
    fun `should return empty but non-null list when all records in a page have unexpected shape`() = runTest {
        val csafNoiseRecord = """
            {
                "document": {"category": "csaf_security_advisory"},
                "product_tree": {},
                "vulnerabilities": [],
                "containers": {}
            }
        """.trimIndent()

        val mockEngine = MockEngine {
            respond(
                content = "[$csafNoiseRecord]",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerabilitiesSince("2026-07-01T00:00:00")

        assertNotNull(result)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should return null for non-success status on incremental fetch`() = runTest {
        val mockEngine = MockEngine {
            respond(content = "Internal Server Error", status = HttpStatusCode.InternalServerError)
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerabilitiesSince("2026-07-01T00:00:00")

        assertNull(result)
    }

    @Test
    fun `should return empty list for empty array response`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = "[]",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerabilitiesSince("2026-07-01T00:00:00")

        assertNotNull(result)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should retry after 429 honoring Retry-After header`() = runTest {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            if (requestCount < 3) {
                respond(
                    content = "Rate limit exceeded",
                    status = HttpStatusCode.TooManyRequests,
                    headers = headersOf(HttpHeaders.RetryAfter, "1")
                )
            } else {
                respond(
                    content = GcveModelsTest.LOG4J_RESPONSE,
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-2021-44228")

        assertNotNull(result)
        assertEquals(3, requestCount)
    }

    @Test
    fun `should return null after exhausting retries on persistent 429`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine {
            requestCount++
            respond(
                content = "Rate limit exceeded",
                status = HttpStatusCode.TooManyRequests,
                headers = headersOf(HttpHeaders.RetryAfter, "1")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-2021-44228")

        assertNull(result)
        assertEquals(4, requestCount) // initial + 3 retries
    }

    @Test
    fun `should retry on 503 and eventually succeed`() = runTest {
        var requestCount = 0

        val mockEngine = MockEngine {
            requestCount++
            if (requestCount < 2) {
                respond(content = "Service Unavailable", status = HttpStatusCode.ServiceUnavailable)
            } else {
                respond(
                    content = GcveModelsTest.LOG4J_RESPONSE,
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-2021-44228")

        assertNotNull(result)
        assertEquals(2, requestCount)
    }

    @Test
    fun `should open circuit breaker after repeated failures`() = runTest {
        val circuitBreaker = InMemoryCircuitBreaker(failureThreshold = 2, openDurationSeconds = 300)

        val mockEngine = MockEngine {
            respond(content = "Internal Server Error", status = HttpStatusCode.InternalServerError)
        }

        val client = createClient(mockEngine, circuitBreaker = circuitBreaker)

        client.getVulnerability("CVE-2021-44228")
        client.getVulnerability("CVE-2024-3094")

        assertTrue(circuitBreaker.isOpen())

        val result = client.getVulnerability("CVE-2024-0001")
        assertNull(result)
    }

    @Test
    fun `should return null when circuit breaker is open`() = runTest {
        val circuitBreaker = InMemoryCircuitBreaker(failureThreshold = 1, openDurationSeconds = 300)
        circuitBreaker.recordFailure()

        assertTrue(circuitBreaker.isOpen())

        val mockEngine = MockEngine {
            fail("Should not make HTTP request when circuit breaker is open")
        }

        val client = createClient(mockEngine, circuitBreaker = circuitBreaker)
        val result = client.getVulnerability("CVE-2021-44228")

        assertNull(result)
    }

    @Test
    fun `should reset circuit breaker on success`() = runTest {
        val circuitBreaker = InMemoryCircuitBreaker(failureThreshold = 3, openDurationSeconds = 300)
        circuitBreaker.recordFailure()
        circuitBreaker.recordFailure()

        assertFalse(circuitBreaker.isOpen())

        val mockEngine = MockEngine {
            respond(
                content = GcveModelsTest.LOG4J_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine, circuitBreaker = circuitBreaker)
        val result = client.getVulnerability("CVE-2021-44228")

        assertNotNull(result)
        assertFalse(circuitBreaker.isOpen())
    }

    @Test
    fun `should return null when circuit breaker is open for incremental fetch`() = runTest {
        val circuitBreaker = InMemoryCircuitBreaker(failureThreshold = 1, openDurationSeconds = 300)
        circuitBreaker.recordFailure()

        val mockEngine = MockEngine {
            fail("Should not make HTTP request when circuit breaker is open")
        }

        val client = createClient(mockEngine, circuitBreaker = circuitBreaker)
        val result = client.getVulnerabilitiesSince("2026-07-01T00:00:00")

        assertNull(result)
    }

    @Test
    fun `should handle non-JSON error response gracefully`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = "<html>502 Bad Gateway</html>",
                status = HttpStatusCode.BadGateway,
                headers = headersOf(HttpHeaders.ContentType, "text/html")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getVulnerability("CVE-2021-44228")

        assertNull(result)
    }

    @Test
    fun `should fetch EPSS score for a vulnerability`() = runTest {
        val mockEngine = MockEngine { request ->
            assertEquals("$mockBaseUrl/epss/CVE-2021-44228", request.url.toString())
            respond(
                content = GcveModelsTest.EPSS_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createClient(mockEngine)
        val result = client.getEpssScore("CVE-2021-44228")

        assertNotNull(result)
        assertEquals("CVE-2021-44228", result.cve)
        assertEquals("0.99999", result.epss)
    }

    @Test
    fun `should return null EPSS for 404`() = runTest {
        val mockEngine = MockEngine {
            respond(content = "Not Found", status = HttpStatusCode.NotFound)
        }

        val client = createClient(mockEngine)
        val result = client.getEpssScore("CVE-9999-99999")

        assertNull(result)
    }
}
