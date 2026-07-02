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

class GcveMissPathServiceTest {

    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        coerceInputValues = true
    }

    private val mockBaseUrl = "https://test.gcve.eu/api"

    private fun createGcveClient(mockEngine: MockEngine): GcveClient {
        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) { json(json) }
        }
        return GcveClient(httpClient, mockBaseUrl, null, InMemoryCircuitBreaker())
    }

    @Test
    fun `should fetch and store CVE not in GCVE table`() = runTest {
        val gcveRepository = InMemoryGcveRepository()

        val mockEngine = MockEngine {
            respond(
                content = GcveModelsTest.LOG4J_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createGcveClient(mockEngine)
        val service = GcveMissPathService(client, gcveRepository)

        val result = service.fetchIfMissing("CVE-2021-44228")

        assertTrue(result)
        assertNotNull(gcveRepository.getCveData("CVE-2021-44228"))
    }

    @Test
    fun `should skip CVE already in GCVE table`() = runTest {
        val gcveRepository = InMemoryGcveRepository()
        val existingData = GcveCveData(
            cveId = "CVE-2021-44228", cnaSource = "apache",
            publishedDate = null, lastUpdatedDate = null, description = "existing",
            cvssV31Score = 10.0, cvssV31Severity = "CRITICAL", cvssV31Vector = null,
            cvssV40Score = null, cvssV40Severity = null, cvssV40Vector = null,
            cweIds = emptyList(), references = emptyList(),
            hasExploitReference = false, hasPatchReference = false,
            ssvcExploitation = null, ssvcAutomatable = null, ssvcTechnicalImpact = null,
            hasKevEntry = false, kevDateAdded = null, daysOld = 0, daysSinceModified = 0,
        )
        gcveRepository.upsertCve(existingData)

        val mockEngine = MockEngine {
            fail("Should not make HTTP request for already-cached CVE")
        }

        val client = createGcveClient(mockEngine)
        val service = GcveMissPathService(client, gcveRepository)

        val result = service.fetchIfMissing("CVE-2021-44228")
        assertFalse(result)
    }

    @Test
    fun `should handle API returning null gracefully`() = runTest {
        val gcveRepository = InMemoryGcveRepository()

        val mockEngine = MockEngine {
            respond(content = "Not Found", status = HttpStatusCode.NotFound)
        }

        val client = createGcveClient(mockEngine)
        val service = GcveMissPathService(client, gcveRepository)

        val result = service.fetchIfMissing("CVE-9999-99999")

        assertFalse(result)
        assertNull(gcveRepository.getCveData("CVE-9999-99999"))
    }

    @Test
    fun `should fetch multiple missing CVEs in batch`() = runTest {
        val gcveRepository = InMemoryGcveRepository()
        val existingData = GcveCveData(
            cveId = "CVE-2024-3094", cnaSource = "redhat",
            publishedDate = null, lastUpdatedDate = null, description = "existing",
            cvssV31Score = 10.0, cvssV31Severity = "CRITICAL", cvssV31Vector = null,
            cvssV40Score = null, cvssV40Severity = null, cvssV40Vector = null,
            cweIds = emptyList(), references = emptyList(),
            hasExploitReference = false, hasPatchReference = false,
            ssvcExploitation = null, ssvcAutomatable = null, ssvcTechnicalImpact = null,
            hasKevEntry = false, kevDateAdded = null, daysOld = 0, daysSinceModified = 0,
        )
        gcveRepository.upsertCve(existingData)

        var fetchCount = 0
        val mockEngine = MockEngine {
            fetchCount++
            respond(
                content = GcveModelsTest.LOG4J_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createGcveClient(mockEngine)
        val service = GcveMissPathService(client, gcveRepository)

        val fetched = service.fetchMissing(listOf("CVE-2021-44228", "CVE-2024-3094", "CVE-2026-54431"))

        assertEquals(2, fetched)
        assertEquals(2, fetchCount)
    }

    @Test
    fun `should not block on fetch failure`() = runTest {
        val gcveRepository = InMemoryGcveRepository()
        var fetchCount = 0

        val mockEngine = MockEngine {
            fetchCount++
            respond(content = "Internal Server Error", status = HttpStatusCode.InternalServerError)
        }

        val client = createGcveClient(mockEngine)
        val service = GcveMissPathService(client, gcveRepository)

        val result = service.fetchIfMissing("CVE-2021-44228")

        assertFalse(result)
        assertEquals(0, gcveRepository.cveCount())
    }
}
