package no.nav.tpt.infrastructure.nvd

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class NvdClientTest {

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    private val mockBaseUrl = "https://api.test.nvd"

    private fun createMockClient(
        mockEngine: MockEngine,
        apiKey: String? = null
    ): NvdClient {
        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }
        return NvdClient(httpClient, apiKey, mockBaseUrl)
    }

    @Test
    fun `should fetch CVEs by modified date with correct parameters`() = runTest {
        val mockCve = NvdTestDataBuilder.buildCveItem(
            id = "CVE-2024-1234",
            published = "2024-01-15T10:00:00.000Z",
            lastModified = "2024-01-16T12:30:00.000Z"
        )
        val response = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = listOf(NvdTestDataBuilder.buildVulnerabilityItem(mockCve)),
            totalResults = 1
        )

        val mockEngine = MockEngine { request ->
            assertEquals(mockBaseUrl, request.url.toString().substringBefore('?'))
            assertTrue(request.url.parameters.contains("lastModStartDate"))
            assertTrue(request.url.parameters.contains("lastModEndDate"))

            val startDate = request.url.parameters["lastModStartDate"]!!
            val endDate = request.url.parameters["lastModEndDate"]!!

            assertTrue(startDate.matches(Regex("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z")))
            assertTrue(endDate.matches(Regex("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z")))

            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val nvdClient = createMockClient(mockEngine)
        val result = nvdClient.getCvesByModifiedDate(
            lastModStartDate = java.time.LocalDateTime.of(2024, 1, 1, 0, 0, 0),
            lastModEndDate = java.time.LocalDateTime.of(2024, 1, 2, 0, 0, 0)
        )

        assertEquals(1, result.totalResults)
        assertEquals(1, result.vulnerabilities.size)
    }

    @Test
    fun `should fetch CVE by ID and return null when not found`() = runTest {
        val response = NvdTestDataBuilder.buildNvdResponse(vulnerabilities = emptyList())

        val mockEngine = MockEngine { request ->
            assertEquals("CVE-NOTFOUND", request.url.parameters["cveId"])

            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val nvdClient = createMockClient(mockEngine)
        val result = nvdClient.getCveByCveId("CVE-NOTFOUND")

        assertNull(result)
    }

    @Test
    fun `should include API key header when provided`() = runTest {
        val response = NvdTestDataBuilder.buildNvdResponse(vulnerabilities = emptyList())

        val mockEngine = MockEngine { request ->
            assertEquals("test-api-key", request.headers["apiKey"])

            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val nvdClient = createMockClient(mockEngine, apiKey = "test-api-key")
        nvdClient.getCveByCveId("CVE-2024-1234")
    }

    @Test
    fun `should throw exception on API error status`() = runTest {
        val mockEngine = MockEngine {
            respondError(
                status = HttpStatusCode.InternalServerError,
                content = "Internal Server Error"
            )
        }

        val nvdClient = createMockClient(mockEngine)

        val exception = assertFailsWith<IllegalStateException> {
            nvdClient.getCvesByModifiedDate(
                lastModStartDate = java.time.LocalDateTime.of(2024, 1, 1, 0, 0, 0),
                lastModEndDate = java.time.LocalDateTime.of(2024, 1, 2, 0, 0, 0)
            )
        }

        assertTrue(exception.message?.contains("500") == true)
    }

    @Test
    fun `should map CVE with CISA KEV data`() = runTest {
        val mockCve = NvdTestDataBuilder.buildCveItem(
            id = "CVE-2024-9999",
            cisaExploitAdd = "2024-01-20",
            cisaActionDue = "2024-02-10",
            cisaRequiredAction = "Apply updates",
            cisaVulnerabilityName = "Critical Bypass"
        )

        val mockEngine = MockEngine { respond("", HttpStatusCode.OK) }
        val nvdClient = createMockClient(mockEngine)

        val result = nvdClient.mapToNvdCveData(mockCve)

        assertEquals("CVE-2024-9999", result.cveId)
        assertEquals(java.time.LocalDate.parse("2024-01-20"), result.cisaExploitAdd)
        assertEquals(java.time.LocalDate.parse("2024-02-10"), result.cisaActionDue)
        assertEquals("Apply updates", result.cisaRequiredAction)
        assertEquals("Critical Bypass", result.cisaVulnerabilityName)
    }

    @Test
    fun `should map CVE with CVSS scores and prioritize primary over secondary`() = runTest {
        val mockCve = NvdTestDataBuilder.buildCveItem(
            cvssV31 = CvssMetricV31(
                source = "nvd@nist.gov",
                type = "Primary",
                cvssData = CvssDataV31("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL")
            ),
            cvssV2 = CvssMetricV2(
                source = "nvd@nist.gov",
                type = "Primary",
                cvssData = CvssDataV2("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5)
            )
        )

        val mockEngine = MockEngine { respond("", HttpStatusCode.OK) }
        val nvdClient = createMockClient(mockEngine)

        val result = nvdClient.mapToNvdCveData(mockCve)

        assertEquals(9.8, result.cvssV31Score)
        assertEquals("CRITICAL", result.cvssV31Severity)
        assertEquals(7.5, result.cvssV2Score)
        assertEquals("HIGH", result.cvssV2Severity)
    }

    @Test
    fun `should extract CWE IDs and detect exploit and patch references`() = runTest {
        val mockCve = NvdTestDataBuilder.buildCveItem(
            references = listOf(
                CveReference("https://example.com/exploit", "source", listOf("Exploit")),
                CveReference("https://example.com/patch", "source", listOf("Patch"))
            ),
            weaknesses = listOf(
                CveWeakness("nvd@nist.gov", "Primary", listOf(
                    WeaknessDescription("en", "CWE-79"),
                    WeaknessDescription("en", "CWE-89")
                ))
            )
        )

        val mockEngine = MockEngine { respond("", HttpStatusCode.OK) }
        val nvdClient = createMockClient(mockEngine)

        val result = nvdClient.mapToNvdCveData(mockCve)

        assertEquals(listOf("CWE-79", "CWE-89"), result.cweIds)
        assertTrue(result.hasExploitReference)
        assertTrue(result.hasPatchReference)
    }

    @Test
    fun `should parse timestamps with and without timezone suffix`() = runTest {
        val cveWithZ = NvdTestDataBuilder.buildCveItem(
            published = "2024-01-15T10:00:00.000Z",
            lastModified = "2024-01-16T12:30:00.000Z"
        )
        val cveWithoutZ = NvdTestDataBuilder.buildCveItem(
            published = "2002-01-02T05:00:00.000",
            lastModified = "2002-01-03T10:30:00.000"
        )

        val mockEngine = MockEngine { respond("", HttpStatusCode.OK) }
        val nvdClient = createMockClient(mockEngine)

        val resultWithZ = nvdClient.mapToNvdCveData(cveWithZ)
        val resultWithoutZ = nvdClient.mapToNvdCveData(cveWithoutZ)

        assertNotNull(resultWithZ.publishedDate)
        assertNotNull(resultWithZ.lastModifiedDate)
        assertNotNull(resultWithoutZ.publishedDate)
        assertNotNull(resultWithoutZ.lastModifiedDate)
    }

    @Test
    fun `should handle CVE with no CVSS scores`() = runTest {
        val mockCve = NvdTestDataBuilder.buildCveItem(
            cvssV31 = null,
            cvssV30 = null,
            cvssV2 = null
        )

        val mockEngine = MockEngine { respond("", HttpStatusCode.OK) }
        val nvdClient = createMockClient(mockEngine)

        val result = nvdClient.mapToNvdCveData(mockCve)

        assertNull(result.cvssV31Score)
        assertNull(result.cvssV30Score)
        assertNull(result.cvssV2Score)
    }

    @Test
    fun `should extract English description from multiple languages`() = runTest {
        val mockCve = NvdTestDataBuilder.buildCveItem(
            descriptions = listOf(
                CveDescription("es", "Descripción en español"),
                CveDescription("en", "English description"),
                CveDescription("fr", "Description en français")
            )
        )

        val mockEngine = MockEngine { respond("", HttpStatusCode.OK) }
        val nvdClient = createMockClient(mockEngine)

        val result = nvdClient.mapToNvdCveData(mockCve)

        assertEquals("English description", result.description)
    }
}

