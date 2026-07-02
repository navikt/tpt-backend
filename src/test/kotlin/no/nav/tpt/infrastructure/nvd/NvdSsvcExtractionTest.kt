package no.nav.tpt.infrastructure.nvd

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Fixture shapes here are verified against a real NVD API response, e.g. for CVE-2024-3400:
 *
 * "ssvcV203": [{
 *   "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
 *   "ssvcData": {
 *     "options": [
 *       {"exploitation": "active"},
 *       {"automatable": "yes"},
 *       {"technicalImpact": "total"}
 *     ],
 *     "role": "CISA Coordinator",
 *     "version": "2.0.3"
 *   }
 * }]
 *
 * Two things differ from what you might guess reading the SSVC schema in isolation:
 * - `source` is a UUID assigned per contributing organization, not a domain string like "cisa.gov"
 * - option keys are lowercase camelCase ("exploitation", "automatable", "technicalImpact"),
 *   not the human-readable decision-point names ("Exploitation", "Technical Impact")
 *
 * CISA's contribution is identified via `ssvcData.role == "CISA Coordinator"` instead.
 */
class NvdSsvcExtractionTest {

    private val cisaSourceId = "134c704f-9b21-4f2e-91b3-4a467353bcc0"

    @Test
    fun `should extract all three ssvc fields from cisa coordinator role`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = cisaSourceId,
                    ssvcData = SsvcData(
                        options = listOf(
                            mapOf("exploitation" to "active"),
                            mapOf("automatable" to "yes"),
                            mapOf("technicalImpact" to "total")
                        ),
                        role = "CISA Coordinator"
                    )
                )
            )
        )

        val result = metrics.extractNvdSsvc()

        assertEquals("active", result?.exploitation)
        assertEquals("yes", result?.automatable)
        assertEquals("total", result?.technicalImpact)
    }

    @Test
    fun `should lowercase all extracted values`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = cisaSourceId,
                    ssvcData = SsvcData(
                        options = listOf(
                            mapOf("exploitation" to "PoC"),
                            mapOf("automatable" to "No"),
                            mapOf("technicalImpact" to "Partial")
                        ),
                        role = "CISA Coordinator"
                    )
                )
            )
        )

        val result = metrics.extractNvdSsvc()

        assertEquals("poc", result?.exploitation)
        assertEquals("no", result?.automatable)
        assertEquals("partial", result?.technicalImpact)
    }

    @Test
    fun `should return null when ssvcV203 is absent`() {
        val metrics = CveMetrics()

        val result = metrics.extractNvdSsvc()

        assertNull(result)
    }

    @Test
    fun `should return null when ssvcV203 list is empty`() {
        val metrics = CveMetrics(ssvcV203 = emptyList())

        val result = metrics.extractNvdSsvc()

        assertNull(result)
    }

    @Test
    fun `should return null when no cisa coordinator role present`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = "some-other-org-uuid",
                    ssvcData = SsvcData(
                        options = listOf(mapOf("exploitation" to "active")),
                        role = "Some Other Contributor"
                    )
                )
            )
        )

        val result = metrics.extractNvdSsvc()

        assertNull(result)
    }

    @Test
    fun `should return null when role is missing`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = cisaSourceId,
                    ssvcData = SsvcData(
                        options = listOf(mapOf("exploitation" to "active")),
                        role = null
                    )
                )
            )
        )

        val result = metrics.extractNvdSsvc()

        assertNull(result)
    }

    @Test
    fun `should prefer cisa coordinator entry when multiple sources present`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = "some-other-org-uuid",
                    ssvcData = SsvcData(
                        options = listOf(mapOf("exploitation" to "none")),
                        role = "Some Other Contributor"
                    )
                ),
                SsvcMetric(
                    source = cisaSourceId,
                    ssvcData = SsvcData(
                        options = listOf(
                            mapOf("exploitation" to "active"),
                            mapOf("automatable" to "yes"),
                            mapOf("technicalImpact" to "total")
                        ),
                        role = "CISA Coordinator"
                    )
                )
            )
        )

        val result = metrics.extractNvdSsvc()

        assertEquals("active", result?.exploitation)
    }

    @Test
    fun `should handle partially populated options`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = cisaSourceId,
                    ssvcData = SsvcData(
                        options = listOf(
                            mapOf("exploitation" to "active")
                        ),
                        role = "CISA Coordinator"
                    )
                )
            )
        )

        val result = metrics.extractNvdSsvc()

        assertEquals("active", result?.exploitation)
        assertNull(result?.automatable)
        assertNull(result?.technicalImpact)
    }
}
