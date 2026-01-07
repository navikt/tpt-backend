package no.nav.tpt.infrastructure.nvd

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.assertThrows
import java.time.LocalDateTime
import kotlin.test.*

class NvdSyncServiceTest {

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    @Test
    fun `should sync date range successfully`() = runTest {
        val cves = listOf(
            NvdTestDataBuilder.buildCriticalKevCve(),
            NvdTestDataBuilder.buildHighSeverityWithExploit()
        )
        val response = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = cves.map { NvdTestDataBuilder.buildVulnerabilityItem(it) },
            totalResults = 2,
            resultsPerPage = 2000
        )

        val mockEngine = MockEngine {
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val repository = InMemoryNvdRepository()
        val syncService = NvdSyncService(nvdClient, repository)

        val count = syncService.syncDateRange(
            LocalDateTime.now().minusDays(7),
            LocalDateTime.now()
        )

        assertEquals(2, count)
        assertEquals(2, repository.cveCount())
    }

    @Test
    fun `should handle pagination when syncing large result sets`() = runTest {
        val firstBatch = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = (1..2000).map {
                NvdTestDataBuilder.buildVulnerabilityItem(
                    NvdTestDataBuilder.buildCveItem(id = "CVE-2024-$it")
                )
            },
            totalResults = 3500,
            resultsPerPage = 2000,
            startIndex = 0
        )

        val secondBatch = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = (2001..3500).map {
                NvdTestDataBuilder.buildVulnerabilityItem(
                    NvdTestDataBuilder.buildCveItem(id = "CVE-2024-$it")
                )
            },
            totalResults = 3500,
            resultsPerPage = 2000,
            startIndex = 2000
        )

        var requestCount = 0
        val mockEngine = MockEngine { request ->
            val startIndex = request.url.parameters["startIndex"]?.toInt() ?: 0
            requestCount++

            val responseData = when (startIndex) {
                0 -> firstBatch
                2000 -> secondBatch
                else -> error("Unexpected startIndex: $startIndex")
            }

            respond(
                content = json.encodeToString(responseData),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val repository = InMemoryNvdRepository()
        val syncService = NvdSyncService(nvdClient, repository)

        val count = syncService.syncDateRange(
            LocalDateTime.now().minusDays(7),
            LocalDateTime.now()
        )

        assertEquals(3500, count)
        assertEquals(3500, repository.cveCount())
        assertEquals(2, requestCount) // Should make 2 requests for pagination
    }

    @Test
    fun `should sync single CVE successfully`() = runTest {
        val cve = NvdTestDataBuilder.buildCriticalKevCve()
        val response = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = listOf(NvdTestDataBuilder.buildVulnerabilityItem(cve))
        )

        val mockEngine = MockEngine {
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val repository = InMemoryNvdRepository()
        val syncService = NvdSyncService(nvdClient, repository)

        val result = syncService.syncSingleCve("CVE-2024-9999")

        assertNotNull(result)
        assertEquals("CVE-2024-9999", result.cveId)
        assertEquals(1, repository.cveCount())
    }

    @Test
    fun `should return null when syncing non-existent CVE`() = runTest {
        val response = NvdTestDataBuilder.buildNvdResponse(vulnerabilities = emptyList())

        val mockEngine = MockEngine {
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val repository = InMemoryNvdRepository()
        val syncService = NvdSyncService(nvdClient, repository)

        val result = syncService.syncSingleCve("CVE-9999-NOTFOUND")

        assertNull(result)
        assertEquals(0, repository.cveCount())
    }

    @Test
    fun `should perform incremental sync using last modified date`() = runTest {
        val repository = InMemoryNvdRepository()

        // Seed with existing CVE
        repository.upsertCve(
            NvdTestDataBuilder.buildNvdCveData(
                cveId = "CVE-2024-OLD",
                lastModifiedDate = LocalDateTime.of(2024, 1, 1, 12, 0)
            )
        )

        val newCve = NvdTestDataBuilder.buildCriticalKevCve()
        val response = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = listOf(NvdTestDataBuilder.buildVulnerabilityItem(newCve))
        )

        val mockEngine = MockEngine { request ->
            val startDate = request.url.parameters["lastModStartDate"]
            assertNotNull(startDate)
            assertTrue(startDate.contains("2024-01-01"))

            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val syncService = NvdSyncService(nvdClient, repository)

        syncService.performIncrementalSync()

        assertEquals(2, repository.cveCount()) // Old + new
    }

    @Test
    fun `should use default lookback when no data exists for incremental sync`() = runTest {
        val repository = InMemoryNvdRepository() // Empty

        val cve = NvdTestDataBuilder.buildCriticalKevCve()
        val response = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = listOf(NvdTestDataBuilder.buildVulnerabilityItem(cve))
        )

        val mockEngine = MockEngine { request ->
            val startDate = request.url.parameters["lastModStartDate"]
            assertNotNull(startDate)
            // Should use 7 days ago as default

            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val syncService = NvdSyncService(nvdClient, repository)

        syncService.performIncrementalSync()

        assertEquals(1, repository.cveCount())
    }

    @Test
    fun `should handle empty response gracefully`() = runTest {
        val response = NvdTestDataBuilder.buildNvdResponse(vulnerabilities = emptyList())

        val mockEngine = MockEngine {
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val repository = InMemoryNvdRepository()
        val syncService = NvdSyncService(nvdClient, repository)

        val count = syncService.syncDateRange(
            LocalDateTime.now().minusDays(7),
            LocalDateTime.now()
        )

        assertEquals(0, count)
        assertEquals(0, repository.cveCount())
    }

    @Test
    fun `should propagate errors from NVD API`() = runTest {
        val mockEngine = MockEngine {
            respond(
                content = """{"error": "Rate limit exceeded"}""",
                status = HttpStatusCode.TooManyRequests,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val repository = InMemoryNvdRepository()
        val syncService = NvdSyncService(nvdClient, repository)

        assertThrows<Exception> {
            syncService.syncDateRange(
                LocalDateTime.now().minusDays(7),
                LocalDateTime.now()
            )
        }
    }
}

/**
 * Simple in-memory repository for testing NvdSyncService without database dependencies
 */
class InMemoryNvdRepository : NvdRepository {
    private val cves = mutableMapOf<String, NvdCveData>()

    override suspend fun getCveData(cveId: String): NvdCveData? = cves[cveId]

    override suspend fun getCveDataBatch(cveIds: List<String>): Map<String, NvdCveData> =
        cves.filterKeys { it in cveIds }

    override suspend fun upsertCve(cve: NvdCveData): UpsertStats {
        val isUpdate = cves.containsKey(cve.cveId)
        cves[cve.cveId] = cve
        return if (isUpdate) UpsertStats(0, 1) else UpsertStats(1, 0)
    }

    override suspend fun upsertCves(cves: List<NvdCveData>): UpsertStats {
        var added = 0
        var updated = 0
        cves.forEach { cve ->
            val stats = upsertCve(cve)
            added += stats.added
            updated += stats.updated
        }
        return UpsertStats(added, updated)
    }

    override suspend fun getLastModifiedDate(): LocalDateTime? =
        cves.values.maxByOrNull { it.lastModifiedDate }?.lastModifiedDate

    override suspend fun getCvesInKev(): List<NvdCveData> =
        cves.values.filter { it.cisaExploitAdd != null }

    fun cveCount(): Int = cves.size

    fun clear() = cves.clear()
}

