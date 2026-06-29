package no.nav.tpt.infrastructure.nvd

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class NvdSsvcExtractionTest {

    @Test
    fun `should extract all three ssvc fields from cisa source`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = "cisa.gov",
                    ssvcData = SsvcData(
                        options = listOf(
                            mapOf("Exploitation" to "Active"),
                            mapOf("Automatable" to "Yes"),
                            mapOf("Technical Impact" to "Total")
                        )
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
                    source = "cisa.gov",
                    ssvcData = SsvcData(
                        options = listOf(
                            mapOf("Exploitation" to "PoC"),
                            mapOf("Automatable" to "No"),
                            mapOf("Technical Impact" to "Partial")
                        )
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
    fun `should return null when no cisa source present`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = "other.org",
                    ssvcData = SsvcData(
                        options = listOf(mapOf("Exploitation" to "Active"))
                    )
                )
            )
        )

        val result = metrics.extractNvdSsvc()

        assertNull(result)
    }

    @Test
    fun `should prefer cisa source when multiple sources present`() {
        val metrics = CveMetrics(
            ssvcV203 = listOf(
                SsvcMetric(
                    source = "other.org",
                    ssvcData = SsvcData(options = listOf(mapOf("Exploitation" to "None")))
                ),
                SsvcMetric(
                    source = "cisa.gov",
                    ssvcData = SsvcData(
                        options = listOf(
                            mapOf("Exploitation" to "Active"),
                            mapOf("Automatable" to "Yes"),
                            mapOf("Technical Impact" to "Total")
                        )
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
                    source = "cisa.gov",
                    ssvcData = SsvcData(
                        options = listOf(
                            mapOf("Exploitation" to "Active")
                        )
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
