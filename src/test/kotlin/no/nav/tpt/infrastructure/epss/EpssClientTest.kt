package no.nav.tpt.infrastructure.epss

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.*

class EpssClientTest {

    private val testBaseUrl = "http://localhost:8080/mock-epss-api"

    @Test
    fun `should fetch EPSS scores for single CVE`() = runTest {
        val mockEngine = MockEngine { request ->
            assertEquals("$testBaseUrl/epss?cve=CVE-2021-44228", request.url.toString())
            respond(
                content = """
                    {
                        "status": "OK",
                        "status-code": 200,
                        "total": 1,
                        "data": [
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.942510000",
                                "percentile": "0.999630000",
                                "date": "2025-11-20"
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
        val response = epssClient.getEpssScores(listOf("CVE-2021-44228"))

        assertEquals("OK", response.status)
        assertEquals(1, response.total)
        assertEquals(1, response.data.size)
        assertEquals("CVE-2021-44228", response.data[0].cve)
        assertEquals("0.942510000", response.data[0].epss)
        assertEquals("0.999630000", response.data[0].percentile)
        assertEquals("2025-11-20", response.data[0].date)
    }

    @Test
    fun `should fetch EPSS scores for multiple CVEs`() = runTest {
        val mockEngine = MockEngine { request ->
            assertTrue(request.url.toString().contains("CVE-2021-44228"))
            assertTrue(request.url.toString().contains("CVE-2022-22965"))
            respond(
                content = """
                    {
                        "status": "OK",
                        "status-code": 200,
                        "total": 2,
                        "data": [
                            {
                                "cve": "CVE-2022-22965",
                                "epss": "0.943870000",
                                "percentile": "0.999930000",
                                "date": "2025-11-20"
                            },
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.942510000",
                                "percentile": "0.999630000",
                                "date": "2025-11-20"
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
        val response = epssClient.getEpssScores(listOf("CVE-2021-44228", "CVE-2022-22965"))

        assertEquals("OK", response.status)
        assertEquals(2, response.total)
        assertEquals(2, response.data.size)

        val cve1 = response.data.find { it.cve == "CVE-2021-44228" }
        assertNotNull(cve1)
        assertEquals("0.942510000", cve1.epss)

        val cve2 = response.data.find { it.cve == "CVE-2022-22965" }
        assertNotNull(cve2)
        assertEquals("0.943870000", cve2.epss)
    }

    @Test
    fun `should return empty response for empty CVE list`() = runTest {
        val mockEngine = MockEngine { _ ->
            fail("Should not make HTTP request for empty CVE list")
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)
        val response = epssClient.getEpssScores(emptyList())

        assertEquals("OK", response.status)
        assertEquals(0, response.total)
        assertTrue(response.data.isEmpty())
    }

    @Test
    fun `should return empty data for CVE not found`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = """
                    {
                        "status": "OK",
                        "status-code": 200,
                        "total": 0,
                        "data": []
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
        val response = epssClient.getEpssScores(listOf("CVE-9999-99999"))

        assertEquals("OK", response.status)
        assertEquals(0, response.total)
        assertTrue(response.data.isEmpty())
    }

    @Test
    fun `should throw EpssRateLimitException on 429 response`() = runTest {
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

        assertFailsWith<EpssRateLimitException> {
            epssClient.getEpssScores(listOf("CVE-2021-44228"))
        }
    }

    @Test
    fun `should throw EpssApiException on 500 response`() = runTest {
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

        assertFailsWith<EpssApiException> {
            epssClient.getEpssScores(listOf("CVE-2021-44228"))
        }
    }

    @Test
    fun `should throw EpssApiException on 400 response`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = "Bad Request",
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, "text/plain")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient, testBaseUrl)

        assertFailsWith<EpssApiException> {
            epssClient.getEpssScores(listOf("CVE-2021-44228"))
        }
    }
}

