package no.nav.tpt.infrastructure.epss

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.*

class EpssServiceImplTest {

    private val testBaseUrl = "http://localhost:8080/mock-epss-api"

    private class InMemoryEpssRepository : EpssRepository {
        private val storage = mutableMapOf<String, EpssScore>()
        private val staleCves = mutableSetOf<String>()
        val upsertedScores = mutableListOf<EpssScore>()

        override suspend fun getEpssScore(cveId: String): EpssScore? = storage[cveId]

        override suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore> {
            return cveIds.mapNotNull { cveId -> storage[cveId]?.let { cveId to it } }.toMap()
        }

        override suspend fun upsertEpssScore(score: EpssScore) {
            storage[score.cve] = score
            upsertedScores.add(score)
            staleCves.remove(score.cve)
        }

        override suspend fun upsertEpssScores(scores: List<EpssScore>) {
            scores.forEach { score ->
                storage[score.cve] = score
                upsertedScores.add(score)
                staleCves.remove(score.cve)
            }
        }

        override suspend fun getStaleCves(cveIds: List<String>, staleThresholdHours: Int): List<String> {
            return cveIds.filter { !storage.containsKey(it) || staleCves.contains(it) }
        }

        fun setStaleCves(cveIds: List<String>) {
            staleCves.addAll(cveIds)
        }
    }

    @Test
    fun `should fetch from database when all CVEs are fresh`() = runTest {
        val mockEngine = MockEngine { _ ->
            fail("Should not make HTTP request when all CVEs are fresh")
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        repository.upsertEpssScore(
            EpssScore("CVE-2021-44228", "0.942510000", "0.999630000", "2026-01-20")
        )

        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val result = service.getEpssScores(listOf("CVE-2021-44228"))
        assertEquals(1, result.size)
        assertEquals("0.942510000", result["CVE-2021-44228"]?.epss)
    }

    @Test
    fun `should fetch fresh data for missing CVEs`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { _ ->
            requestCount++
            respond(
                content = """
                    {
                        "status": "OK",
                        "total": 1,
                        "data": [
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.942510000",
                                "percentile": "0.999630000",
                                "date": "2026-01-20"
                            }
                        ]
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val result = service.getEpssScores(listOf("CVE-2021-44228"))

        assertEquals(1, result.size)
        assertEquals("0.942510000", result["CVE-2021-44228"]?.epss)
        assertEquals(1, requestCount)
        assertEquals(1, repository.upsertedScores.size)
    }

    @Test
    fun `should fetch fresh data for stale CVEs`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { _ ->
            requestCount++
            respond(
                content = """
                    {
                        "status": "OK",
                        "total": 1,
                        "data": [
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.950000000",
                                "percentile": "0.999999000",
                                "date": "2026-01-20"
                            }
                        ]
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        repository.upsertEpssScore(
            EpssScore("CVE-2021-44228", "0.900000000", "0.950000000", "2026-01-19")
        )
        repository.setStaleCves(listOf("CVE-2021-44228"))

        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val result = service.getEpssScores(listOf("CVE-2021-44228"))

        assertEquals(1, result.size)
        assertEquals("0.950000000", result["CVE-2021-44228"]?.epss)
        assertEquals(1, requestCount)
        assertTrue(repository.upsertedScores.size >= 1)
    }

    @Test
    fun `should handle partial hits with some fresh and some stale`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { _ ->
            requestCount++
            respond(
                content = """
                    {
                        "status": "OK",
                        "total": 1,
                        "data": [
                            {
                                "cve": "CVE-2022-22965",
                                "epss": "0.943870000",
                                "percentile": "0.999930000",
                                "date": "2026-01-20"
                            }
                        ]
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        repository.upsertEpssScore(
            EpssScore("CVE-2021-44228", "0.942510000", "0.999630000", "2026-01-20")
        )

        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val result = service.getEpssScores(listOf("CVE-2021-44228", "CVE-2022-22965"))

        assertEquals(2, result.size)
        assertEquals("0.942510000", result["CVE-2021-44228"]?.epss)
        assertEquals("0.943870000", result["CVE-2022-22965"]?.epss)
        assertEquals(1, requestCount)
    }

    @Test
    fun `should return database scores when circuit breaker is open`() = runTest {
        val mockEngine = MockEngine { _ ->
            fail("Should not make HTTP request when circuit breaker is open")
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        repository.upsertEpssScore(
            EpssScore("CVE-2021-44228", "0.900000000", "0.950000000", "2026-01-19")
        )
        repository.setStaleCves(listOf("CVE-2021-44228"))

        val circuitBreaker = MockCircuitBreaker(open = true)
        val service = EpssServiceImpl(epssClient, repository, circuitBreaker)

        val result = service.getEpssScores(listOf("CVE-2021-44228"))

        assertEquals(1, result.size)
        assertEquals("0.900000000", result["CVE-2021-44228"]?.epss)
    }

    @Test
    fun `should open circuit breaker on rate limit`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = "Too Many Requests",
                status = HttpStatusCode.TooManyRequests,
                headers = headersOf(HttpHeaders.ContentType, "text/plain")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        val circuitBreaker = MockCircuitBreaker()
        val service = EpssServiceImpl(epssClient, repository, circuitBreaker)

        val result = service.getEpssScores(listOf("CVE-2021-44228"))

        assertTrue(result.isEmpty())
        assertTrue(circuitBreaker.isOpen())
    }

    @Test
    fun `should filter out invalid CVE IDs`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            val cveParam = request.url.parameters["cve"] ?: ""
            assertFalse(cveParam.contains("INVALID"))
            assertFalse(cveParam.contains("CVE-123"))
            assertTrue(cveParam.contains("CVE-2021-44228"))

            respond(
                content = """
                    {
                        "status": "OK",
                        "total": 1,
                        "data": [
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.942510000",
                                "percentile": "0.999630000",
                                "date": "2026-01-20"
                            }
                        ]
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val result = service.getEpssScores(listOf("CVE-2021-44228", "INVALID-CVE", "CVE-123", "not-a-cve"))

        assertEquals(1, result.size)
        assertEquals("CVE-2021-44228", result.keys.first())
        assertEquals(1, requestCount)
    }

    @Test
    fun `should return empty map when all CVE IDs are invalid`() = runTest {
        val mockEngine = MockEngine { _ ->
            fail("Should not make HTTP request when all CVEs are invalid")
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val result = service.getEpssScores(listOf("INVALID-CVE", "CVE-123", "not-a-cve"))
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should batch requests when CVE parameter exceeds 2000 characters`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            val cveParam = request.url.parameters["cve"] ?: ""
            assertTrue(cveParam.length <= 2000, "CVE parameter length ${cveParam.length} exceeds 2000 characters")

            val cves = cveParam.split(",")
            val data = cves.joinToString(",") {
                """
                {
                    "cve": "$it",
                    "epss": "0.001230000",
                    "percentile": "0.456780000",
                    "date": "2026-01-20"
                }
                """.trimIndent()
            }

            respond(
                content = """
                    {
                        "status": "OK",
                        "total": ${cves.size},
                        "data": [$data]
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val largeCveList = (1..150).map { "CVE-2023-${it.toString().padStart(5, '0')}" }
        val paramLength = largeCveList.joinToString(",").length
        assertTrue(paramLength > 2000, "Test setup: CVE list should exceed 2000 chars, got $paramLength")

        val result = service.getEpssScores(largeCveList)

        assertEquals(150, result.size)
        assertTrue(requestCount > 1, "Should have made multiple requests for batching")
    }

    @Test
    fun `should return empty map for empty CVE list`() = runTest {
        val mockEngine = MockEngine { _ ->
            fail("Should not make HTTP request for empty CVE list")
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val result = service.getEpssScores(emptyList())
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should handle API errors gracefully`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = "Internal Server Error",
                status = HttpStatusCode.InternalServerError,
                headers = headersOf(HttpHeaders.ContentType, "text/plain")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val repository = InMemoryEpssRepository()
        repository.upsertEpssScore(
            EpssScore("CVE-2021-44228", "0.900000000", "0.950000000", "2026-01-19")
        )
        repository.setStaleCves(listOf("CVE-2021-44228"))

        val service = EpssServiceImpl(epssClient, repository, MockCircuitBreaker())

        val result = service.getEpssScores(listOf("CVE-2021-44228"))

        assertEquals(1, result.size)
        assertEquals("0.900000000", result["CVE-2021-44228"]?.epss)
    }
}
