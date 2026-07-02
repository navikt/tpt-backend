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

class GcveSyncServiceTest {

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
    fun `should only upsert CVEs that exist in tracked set`() = runTest {
        val gcveRepository = InMemoryGcveRepository()
        val trackedCveIds = setOf("CVE-2026-54431")

        val mockEngine = MockEngine {
            respond(
                content = GcveModelsTest.LIST_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createGcveClient(mockEngine)
        val syncService = GcveSyncService(client, gcveRepository)

        val count = syncService.performIncrementalSync(
            since = "2026-07-01T00:00:00",
            trackedCveIds = trackedCveIds,
        )

        assertEquals(1, count)
        assertNotNull(gcveRepository.getCveData("CVE-2026-54431"))
        assertNull(gcveRepository.getCveData("CVE-2026-54430"))
    }

    @Test
    fun `should upsert all CVEs when tracked set is not provided`() = runTest {
        val gcveRepository = InMemoryGcveRepository()

        val mockEngine = MockEngine {
            respond(
                content = GcveModelsTest.LIST_RESPONSE,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createGcveClient(mockEngine)
        val syncService = GcveSyncService(client, gcveRepository)

        val count = syncService.performIncrementalSync(since = "2026-07-01T00:00:00")

        assertEquals(2, count)
    }

    @Test
    fun `should paginate through multiple pages`() = runTest {
        val gcveRepository = InMemoryGcveRepository()
        var requestCount = 0

        val record = json.decodeFromString<GcveCveRecord>(GcveModelsTest.CVSS_V4_RESPONSE)
        val fullPage = (1..100).map {
            json.encodeToString(
                GcveCveRecord.serializer(),
                record.copy(cveMetadata = record.cveMetadata.copy(cveId = "CVE-2026-$it"))
            )
        }.joinToString(",", prefix = "[", postfix = "]")

        val mockEngine = MockEngine { request ->
            requestCount++
            val page = request.url.parameters["page"]?.toInt() ?: 1
            when (page) {
                1 -> respond(
                    content = fullPage,
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
                else -> respond(
                    content = "[]",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
        }

        val client = createGcveClient(mockEngine)
        val syncService = GcveSyncService(client, gcveRepository)

        val count = syncService.performIncrementalSync(since = "2026-07-01T00:00:00")

        assertEquals(2, requestCount)
        assertEquals(100, count)
    }

    @Test
    fun `should update sync watermark after successful sync`() = runTest {
        val gcveRepository = InMemoryGcveRepository()

        val mockEngine = MockEngine {
            respond(
                content = "[]",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createGcveClient(mockEngine)
        val syncService = GcveSyncService(client, gcveRepository)

        assertNull(gcveRepository.getLastSyncTimestamp())

        syncService.performIncrementalSync(since = "2026-07-01T00:00:00")

        assertNotNull(gcveRepository.getLastSyncTimestamp())
    }

    @Test
    fun `should NOT advance sync watermark when the fetch fails`() = runTest {
        val gcveRepository = InMemoryGcveRepository()

        val mockEngine = MockEngine {
            respond(content = "Internal Server Error", status = HttpStatusCode.InternalServerError)
        }

        val client = createGcveClient(mockEngine)
        val syncService = GcveSyncService(client, gcveRepository)

        assertNull(gcveRepository.getLastSyncTimestamp())

        syncService.performIncrementalSync(since = "2026-07-01T00:00:00")

        assertNull(
            gcveRepository.getLastSyncTimestamp(),
            "Watermark must not advance when the fetch failed, or the failed window is silently skipped forever"
        )
    }

    @Test
    fun `should not advance watermark past a failure encountered on a later page`() = runTest {
        val gcveRepository = InMemoryGcveRepository()

        val record = json.decodeFromString<GcveCveRecord>(GcveModelsTest.CVSS_V4_RESPONSE)
        val fullPage = (1..100).map {
            json.encodeToString(
                GcveCveRecord.serializer(),
                record.copy(cveMetadata = record.cveMetadata.copy(cveId = "CVE-2026-$it"))
            )
        }.joinToString(",", prefix = "[", postfix = "]")

        val mockEngine = MockEngine { request ->
            val page = request.url.parameters["page"]?.toInt() ?: 1
            when (page) {
                1 -> respond(
                    content = fullPage,
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
                else -> respond(content = "Internal Server Error", status = HttpStatusCode.InternalServerError)
            }
        }

        val client = createGcveClient(mockEngine)
        val syncService = GcveSyncService(client, gcveRepository)

        val count = syncService.performIncrementalSync(since = "2026-07-01T00:00:00")

        // Page 1 succeeded and was upserted, but since page 2 failed, the watermark
        // must not advance so the next run retries from the same `since`.
        assertEquals(100, count)
        assertNull(gcveRepository.getLastSyncTimestamp())
    }

    @Test
    fun `should handle empty sweep results`() = runTest {
        val gcveRepository = InMemoryGcveRepository()

        val mockEngine = MockEngine {
            respond(
                content = "[]",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createGcveClient(mockEngine)
        val syncService = GcveSyncService(client, gcveRepository)

        val count = syncService.performIncrementalSync(since = "2026-07-01T00:00:00")

        assertEquals(0, count)
        assertEquals(0, gcveRepository.cveCount())
    }

    @Test
    fun `should store raw response alongside domain data`() = runTest {
        val gcveRepository = InMemoryGcveRepository()

        val mockEngine = MockEngine {
            respond(
                content = "[${GcveModelsTest.LOG4J_RESPONSE}]",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val client = createGcveClient(mockEngine)
        val syncService = GcveSyncService(client, gcveRepository)

        syncService.performIncrementalSync(since = "2020-01-01T00:00:00")

        val result = gcveRepository.getCveDataWithRaw("CVE-2021-44228")
        assertNotNull(result)
        assertNotNull(result.second)
    }
}
