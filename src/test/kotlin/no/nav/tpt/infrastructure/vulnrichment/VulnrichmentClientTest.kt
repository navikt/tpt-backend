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
}
