package no.nav.tpt.infrastructure.vulnrichment

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class VulnrichmentClientTest {

    private val httpClient = HttpClient(MockEngine { respondBadRequest() })
    private val client = VulnrichmentClient(httpClient)

    private fun buildCveJson(
        cveId: String,
        exploitation: String? = null,
        automatable: String? = null,
        technicalImpact: String? = null,
    ): CveJson5 {
        val options = mutableListOf<Map<String, String>>()
        if (exploitation != null) options.add(mapOf("Exploitation" to exploitation))
        if (automatable != null) options.add(mapOf("Automatable" to automatable))
        if (technicalImpact != null) options.add(mapOf("Technical Impact" to technicalImpact))

        return CveJson5(
            cveMetadata = CveMetadata(cveId = cveId),
            containers = CveContainers(
                adp = listOf(
                    AdpContainer(
                        providerMetadata = ProviderMetadata(shortName = "CISA-ADP"),
                        metrics = listOf(
                            AdpMetric(
                                other = OtherMetric(
                                    type = "ssvc",
                                    content = SsvcContent(options = options),
                                )
                            )
                        )
                    )
                )
            )
        )
    }

    @Test
    fun `should extract active exploitation status`() {
        val result = client.extractSsvcDecisions(buildCveJson("CVE-2024-1234", exploitation = "Active"))

        assertEquals("active", result?.exploitationStatus)
    }

    @Test
    fun `should extract poc exploitation status`() {
        val result = client.extractSsvcDecisions(buildCveJson("CVE-2024-1234", exploitation = "PoC"))

        assertEquals("poc", result?.exploitationStatus)
    }

    @Test
    fun `should extract none exploitation status`() {
        val result = client.extractSsvcDecisions(buildCveJson("CVE-2024-1234", exploitation = "None"))

        assertEquals("none", result?.exploitationStatus)
    }

    @Test
    fun `should extract automatable yes`() {
        val result = client.extractSsvcDecisions(buildCveJson("CVE-2024-1234", automatable = "Yes"))

        assertEquals("yes", result?.automatable)
    }

    @Test
    fun `should extract automatable no`() {
        val result = client.extractSsvcDecisions(buildCveJson("CVE-2024-1234", automatable = "No"))

        assertEquals("no", result?.automatable)
    }

    @Test
    fun `should extract technical impact total`() {
        val result = client.extractSsvcDecisions(buildCveJson("CVE-2024-1234", technicalImpact = "Total"))

        assertEquals("total", result?.technicalImpact)
    }

    @Test
    fun `should extract all SSVC fields together`() {
        val result = client.extractSsvcDecisions(
            buildCveJson("CVE-2024-9999", exploitation = "Active", automatable = "Yes", technicalImpact = "Total")
        )

        assertEquals("CVE-2024-9999", result?.cveId)
        assertEquals("active", result?.exploitationStatus)
        assertEquals("yes", result?.automatable)
        assertEquals("total", result?.technicalImpact)
    }

    @Test
    fun `should lowercase all extracted values`() {
        val result = client.extractSsvcDecisions(
            buildCveJson("CVE-2024-1234", exploitation = "ACTIVE", automatable = "YES", technicalImpact = "TOTAL")
        )

        assertEquals("active", result?.exploitationStatus)
        assertEquals("yes", result?.automatable)
        assertEquals("total", result?.technicalImpact)
    }

    @Test
    fun `should return null when cveMetadata is missing`() {
        val cveJson = CveJson5(cveMetadata = null, containers = null)

        val result = client.extractSsvcDecisions(cveJson)

        assertNull(result)
    }

    @Test
    fun `should return null when containers is missing`() {
        val cveJson = CveJson5(
            cveMetadata = CveMetadata(cveId = "CVE-2024-1234"),
            containers = null
        )

        val result = client.extractSsvcDecisions(cveJson)

        assertNull(result)
    }

    @Test
    fun `should return null when no CISA-ADP container present`() {
        val cveJson = CveJson5(
            cveMetadata = CveMetadata(cveId = "CVE-2024-1234"),
            containers = CveContainers(
                adp = listOf(
                    AdpContainer(providerMetadata = ProviderMetadata(shortName = "OTHER-ADP"))
                )
            )
        )

        val result = client.extractSsvcDecisions(cveJson)

        assertNull(result)
    }

    @Test
    fun `should return null when no SSVC metric in CISA-ADP container`() {
        val cveJson = CveJson5(
            cveMetadata = CveMetadata(cveId = "CVE-2024-1234"),
            containers = CveContainers(
                adp = listOf(
                    AdpContainer(
                        providerMetadata = ProviderMetadata(shortName = "CISA-ADP"),
                        metrics = listOf(
                            AdpMetric(other = OtherMetric(type = "cvss", content = null))
                        )
                    )
                )
            )
        )

        val result = client.extractSsvcDecisions(cveJson)

        assertNull(result)
    }

    @Test
    fun `should return null when CISA-ADP has no metrics`() {
        val cveJson = CveJson5(
            cveMetadata = CveMetadata(cveId = "CVE-2024-1234"),
            containers = CveContainers(
                adp = listOf(
                    AdpContainer(
                        providerMetadata = ProviderMetadata(shortName = "CISA-ADP"),
                        metrics = null
                    )
                )
            )
        )

        val result = client.extractSsvcDecisions(cveJson)

        assertNull(result)
    }

    @Test
    fun `should return null when SSVC options list is empty`() {
        val cveJson = CveJson5(
            cveMetadata = CveMetadata(cveId = "CVE-2024-1234"),
            containers = CveContainers(
                adp = listOf(
                    AdpContainer(
                        providerMetadata = ProviderMetadata(shortName = "CISA-ADP"),
                        metrics = listOf(
                            AdpMetric(
                                other = OtherMetric(
                                    type = "ssvc",
                                    content = SsvcContent(options = null)
                                )
                            )
                        )
                    )
                )
            )
        )

        val result = client.extractSsvcDecisions(cveJson)

        assertNull(result)
    }

    @Test
    fun `should handle missing optional SSVC fields with nulls`() {
        val result = client.extractSsvcDecisions(buildCveJson("CVE-2024-1234", exploitation = "active"))

        assertEquals("CVE-2024-1234", result?.cveId)
        assertEquals("active", result?.exploitationStatus)
        assertNull(result?.automatable)
        assertNull(result?.technicalImpact)
    }

    @Test
    fun `should match CISA-ADP provider name case-insensitively`() {
        val cveJson = CveJson5(
            cveMetadata = CveMetadata(cveId = "CVE-2024-1234"),
            containers = CveContainers(
                adp = listOf(
                    AdpContainer(
                        providerMetadata = ProviderMetadata(shortName = "cisa-adp"),
                        metrics = listOf(
                            AdpMetric(
                                other = OtherMetric(
                                    type = "ssvc",
                                    content = SsvcContent(options = listOf(mapOf("Exploitation" to "active")))
                                )
                            )
                        )
                    )
                )
            )
        )

        val result = client.extractSsvcDecisions(cveJson)

        assertEquals("active", result?.exploitationStatus)
    }

    @Test
    fun `should parse real CVE API response format and extract SSVC decisions`() {
        val realPayload = """
            {
              "dataType": "CVE_RECORD",
              "dataVersion": "5.2",
              "cveMetadata": {
                "cveId": "CVE-2025-59472",
                "assignerOrgId": "36234546-b8fa-4601-9d6f-f4e334aa8ea1",
                "state": "PUBLISHED",
                "assignerShortName": "hackerone",
                "dateReserved": "2025-09-16T15:00:07.876Z",
                "datePublished": "2026-01-26T21:43:05.099Z",
                "dateUpdated": "2026-01-27T14:54:04.986Z"
              },
              "containers": {
                "cna": {
                  "descriptions": [{"lang": "en", "value": "A denial of service vulnerability..."}],
                  "providerMetadata": {
                    "orgId": "36234546-b8fa-4601-9d6f-f4e334aa8ea1",
                    "shortName": "hackerone",
                    "dateUpdated": "2026-01-26T21:43:05.099Z"
                  }
                },
                "adp": [
                  {
                    "title": "CISA ADP Vulnrichment",
                    "providerMetadata": {
                      "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                      "shortName": "CISA-ADP",
                      "dateUpdated": "2026-01-27T14:54:04.986Z"
                    },
                    "metrics": [
                      {
                        "other": {
                          "type": "ssvc",
                          "content": {
                            "timestamp": "2026-01-27T14:52:42.677682Z",
                            "id": "CVE-2025-59472",
                            "options": [
                              {"Exploitation": "none"},
                              {"Automatable": "no"},
                              {"Technical Impact": "partial"}
                            ],
                            "role": "CISA Coordinator",
                            "version": "2.0.3"
                          }
                        }
                      }
                    ]
                  }
                ]
              }
            }
        """.trimIndent()

        val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
        val cveJson = json.decodeFromString<CveJson5>(realPayload)
        val result = client.extractSsvcDecisions(cveJson)

        assertEquals("CVE-2025-59472", result?.cveId)
        assertEquals("none", result?.exploitationStatus)
        assertEquals("no", result?.automatable)
        assertEquals("partial", result?.technicalImpact)
    }

    @Test
    fun `should return null when real response has no CISA-ADP container`() {
        val payloadWithoutAdp = """
            {
              "dataType": "CVE_RECORD",
              "dataVersion": "5.2",
              "cveMetadata": {"cveId": "CVE-2025-11111"},
              "containers": {
                "cna": {
                  "descriptions": [{"lang": "en", "value": "A vulnerability..."}],
                  "providerMetadata": {"shortName": "vendor"}
                }
              }
            }
        """.trimIndent()

        val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }
        val cveJson = json.decodeFromString<CveJson5>(payloadWithoutAdp)
        val result = client.extractSsvcDecisions(cveJson)

        assertNull(result)
    }

    @Test
    fun `should fetch CVE data via HTTP and parse real API response format`() = kotlinx.coroutines.test.runTest {
        val realPayload = """
            {
              "dataType": "CVE_RECORD",
              "dataVersion": "5.2",
              "cveMetadata": {"cveId": "CVE-2025-59472"},
              "containers": {
                "adp": [{
                  "providerMetadata": {"shortName": "CISA-ADP"},
                  "metrics": [{
                    "other": {
                      "type": "ssvc",
                      "content": {
                        "options": [
                          {"Exploitation": "active"},
                          {"Automatable": "yes"},
                          {"Technical Impact": "total"}
                        ]
                      }
                    }
                  }]
                }]
              }
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            if (request.url.encodedPath.contains("CVE-2025-59472")) {
                respond(
                    content = realPayload,
                    headers = io.ktor.http.headersOf(
                        io.ktor.http.HttpHeaders.ContentType,
                        io.ktor.http.ContentType.Application.Json.toString()
                    )
                )
            } else {
                respondBadRequest()
            }
        }
        val fetchClient = VulnrichmentClient(HttpClient(mockEngine))

        val result = fetchClient.fetchCveData("CVE-2025-59472")

        assertEquals("CVE-2025-59472", result?.cveId)
        assertEquals("active", result?.exploitationStatus)
        assertEquals("yes", result?.automatable)
        assertEquals("total", result?.technicalImpact)
    }

    @Test
    fun `should return null when CVE API returns non-success status`() = kotlinx.coroutines.test.runTest {
        val notFoundClient = VulnrichmentClient(HttpClient(MockEngine { respondError(io.ktor.http.HttpStatusCode.NotFound) }))

        val result = notFoundClient.fetchCveData("CVE-2025-99999")

        assertNull(result)
    }

    @Test
    fun `should open circuit breaker after 5 consecutive server errors and skip subsequent requests`() = kotlinx.coroutines.test.runTest {
        var callCount = 0
        val failClient = VulnrichmentClient(HttpClient(MockEngine {
            callCount++
            respondError(io.ktor.http.HttpStatusCode.InternalServerError)
        }))

        repeat(5) { failClient.fetchCveData("CVE-2024-0001") }
        val countAfterFailures = callCount

        val result = failClient.fetchCveData("CVE-2024-0002")

        assertNull(result)
        assertEquals(countAfterFailures, callCount)
    }

    @Test
    fun `should not call API when rate limited by 429 response with Retry-After header`() = kotlinx.coroutines.test.runTest {
        var callCount = 0
        val rateLimitClient = VulnrichmentClient(HttpClient(MockEngine {
            callCount++
            respond(
                content = "",
                status = io.ktor.http.HttpStatusCode.TooManyRequests,
                headers = io.ktor.http.headersOf(io.ktor.http.HttpHeaders.RetryAfter, "60"),
            )
        }))

        rateLimitClient.fetchCveData("CVE-2024-0001")
        val countAfterRateLimit = callCount

        val result = rateLimitClient.fetchCveData("CVE-2024-0002")

        assertNull(result)
        assertEquals(countAfterRateLimit, callCount)
    }

    @Test
    fun `should not call API when ratelimit-remaining is at or below low watermark`() = kotlinx.coroutines.test.runTest {
        var callCount = 0
        val minimalPayload = """{"cveMetadata":{"cveId":"CVE-2024-0001"},"containers":{}}"""
        val rateLimitClient = VulnrichmentClient(HttpClient(MockEngine {
            callCount++
            respond(
                content = minimalPayload,
                headers = io.ktor.http.Headers.build {
                    append(io.ktor.http.HttpHeaders.ContentType, io.ktor.http.ContentType.Application.Json.toString())
                    append("ratelimit-remaining", "500") // below 1000 watermark
                    append("ratelimit-reset", "30")      // seconds until window reset
                },
            )
        }))

        rateLimitClient.fetchCveData("CVE-2024-0001")
        val countAfterExhausted = callCount

        val result = rateLimitClient.fetchCveData("CVE-2024-0002")

        assertNull(result)
        assertEquals(countAfterExhausted, callCount)
    }
}
