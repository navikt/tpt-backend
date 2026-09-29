package no.nav.tpt.infrastructure.gcve

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.common.InMemoryCircuitBreaker
import java.time.LocalDate
import kotlin.test.*

class GcveSightingsSyncServiceTest {

    private val json = Json { ignoreUnknownKeys = true; explicitNulls = false; coerceInputValues = true }

    private fun createClient(mockEngine: MockEngine): GcveClient {
        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) { json(json) }
        }
        return GcveClient(
            httpClient,
            "https://test.gcve.eu/api",
            circuitBreaker = InMemoryCircuitBreaker(failureThreshold = 3, openDurationSeconds = 300),
        )
    }

    private fun sightingJson(type: String, vulnerability: String, ts: String = "2024-06-01T12:00:00Z") =
        """{"type":"$type","creation_timestamp":"$ts","vulnerability":"$vulnerability"}"""

    private fun sightingsEnvelope(vararg entries: String): String {
        val data = entries.joinToString(",")
        val count = entries.size
        return """{"metadata":{"count":$count,"page":1,"per_page":1000},"data":[$data]}"""
    }

    private fun emptySightingsEnvelope() =
        """{"metadata":{"count":0,"page":1,"per_page":1000},"data":[]}"""

    @Test
    fun `should aggregate exploited sightings by CVE and upsert summaries`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = sightingsEnvelope(
                    sightingJson("exploited", "CVE-2024-0001"),
                    sightingJson("exploited", "CVE-2024-0001"),
                    sightingJson("exploited", "CVE-2024-0002"),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val repo = InMemoryGcveSightingsRepository()
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)
        service.sync()

        assertEquals(2, repo.summaryCount())
        assertEquals(2, repo.getSummary("CVE-2024-0001")?.exploitedCount)
        assertEquals(1, repo.getSummary("CVE-2024-0002")?.exploitedCount)
    }

    @Test
    fun `should aggregate poc and seen sightings separately`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = sightingsEnvelope(
                    sightingJson("published-proof-of-concept", "CVE-2024-0001"),
                    sightingJson("published-proof-of-concept", "CVE-2024-0001"),
                    sightingJson("seen", "CVE-2024-0001"),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val repo = InMemoryGcveSightingsRepository()
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)
        service.sync()

        val summary = repo.getSummary("CVE-2024-0001")
        assertNotNull(summary)
        assertEquals(0, summary.exploitedCount)
        assertEquals(2, summary.pocCount)
        assertEquals(1, summary.seenCount)
    }

    @Test
    fun `should ignore confirmed and unknown sighting types`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = sightingsEnvelope(
                    sightingJson("confirmed", "CVE-2024-0001"),
                    sightingJson("unknown-type", "CVE-2024-0001"),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val repo = InMemoryGcveSightingsRepository()
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)
        service.sync()

        assertEquals(0, repo.summaryCount())
    }

    @Test
    fun `should skip non-CVE vulnerability IDs`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = sightingsEnvelope(
                    sightingJson("exploited", "GHSA-1234-5678-abcd"),
                    sightingJson("exploited", "CVE-2024-0001"),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val repo = InMemoryGcveSightingsRepository()
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)
        service.sync()

        assertEquals(1, repo.summaryCount())
        assertNotNull(repo.getSummary("CVE-2024-0001"))
    }

    @Test
    fun `should update sync cursor after successful sync`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = emptySightingsEnvelope(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val repo = InMemoryGcveSightingsRepository()
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)

        assertNull(repo.getLastSyncDate())
        service.sync()
        assertNotNull(repo.getLastSyncDate())
    }

    @Test
    fun `should use stored cursor as date_from on subsequent syncs`() = runTest {
        val storedDate = LocalDate.of(2024, 5, 1)
        var capturedUrl: String? = null

        val mockEngine = MockEngine { request ->
            capturedUrl = request.url.toString()
            respond(
                content = emptySightingsEnvelope(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val repo = InMemoryGcveSightingsRepository()
        repo.updateLastSyncDate(storedDate)
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)
        service.sync()

        assertNotNull(capturedUrl)
        assertTrue(capturedUrl!!.contains("date_from=2024-05-01"), "Expected date_from=2024-05-01 in $capturedUrl")
    }

    @Test
    fun `should not update cursor when API call fails`() = runTest {
        val mockEngine = MockEngine {
            respond(content = "Internal Server Error", status = HttpStatusCode.InternalServerError)
        }

        val repo = InMemoryGcveSightingsRepository()
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)
        service.sync()

        assertNull(repo.getLastSyncDate())
        assertEquals(0, repo.summaryCount())
    }

    @Test
    fun `should track latest timestamp per type`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = sightingsEnvelope(
                    sightingJson("exploited", "CVE-2024-0001", "2024-01-01T00:00:00Z"),
                    sightingJson("exploited", "CVE-2024-0001", "2024-06-15T12:00:00Z"),
                    sightingJson("exploited", "CVE-2024-0001", "2024-03-01T00:00:00Z"),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val repo = InMemoryGcveSightingsRepository()
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)
        service.sync()

        val summary = repo.getSummary("CVE-2024-0001")
        assertNotNull(summary)
        assertEquals(3, summary.exploitedCount)
        val latestAt = summary.latestExploitedAt
        assertNotNull(latestAt)
        assertTrue(latestAt.toString().startsWith("2024-06-15"), "Expected latest to be 2024-06-15, was $latestAt")
    }

    @Test
    fun `should default to 30 days ago when no cursor stored`() = runTest {
        var capturedUrl: String? = null

        val mockEngine = MockEngine { request ->
            capturedUrl = request.url.toString()
            respond(
                content = emptySightingsEnvelope(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }

        val repo = InMemoryGcveSightingsRepository()
        val service = GcveSightingsSyncService(createClient(mockEngine), repo)
        service.sync()

        val expectedDate = LocalDate.now().minusDays(30).toString()
        assertNotNull(capturedUrl)
        assertTrue(capturedUrl!!.contains("date_from=$expectedDate"), "Expected date_from=$expectedDate in $capturedUrl")
    }
}
