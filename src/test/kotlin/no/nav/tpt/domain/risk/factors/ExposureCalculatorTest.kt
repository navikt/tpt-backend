package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext
import kotlin.test.Test
import kotlin.test.assertEquals

class ExposureCalculatorTest {

    private val config = RiskScoringConfig()
    private val calculator = ExposureCalculator(config)

    private fun context(ingressTypes: List<String>) = VulnerabilityRiskContext(
        severity = "HIGH", ingressTypes = ingressTypes,
        hasKevEntry = false, epssScore = null, suppressed = false,
        environment = null, buildDate = null,
    )

    @Test
    fun `should return 20 points for external ingress`() {
        val result = calculator.calculate(context(listOf("EXTERNAL")))
        assertEquals(config.exposureExternalPoints, result.points)
    }

    @Test
    fun `should return 12 points for authenticated ingress`() {
        val result = calculator.calculate(context(listOf("AUTHENTICATED")))
        assertEquals(config.exposureAuthenticatedPoints, result.points)
    }

    @Test
    fun `should return 5 points for internal ingress`() {
        val result = calculator.calculate(context(listOf("INTERNAL")))
        assertEquals(config.exposureInternalPoints, result.points)
    }

    @Test
    fun `should return 0 points for no ingress`() {
        val result = calculator.calculate(context(emptyList()))
        assertEquals(config.exposureNonePoints, result.points)
    }

    @Test
    fun `should prioritize external when multiple types present`() {
        val result = calculator.calculate(context(listOf("INTERNAL", "EXTERNAL", "AUTHENTICATED")))
        assertEquals(config.exposureExternalPoints, result.points)
    }

    @Test
    fun `should prioritize authenticated over internal`() {
        val result = calculator.calculate(context(listOf("INTERNAL", "AUTHENTICATED")))
        assertEquals(config.exposureAuthenticatedPoints, result.points)
    }

    @Test
    fun `should return 0 points for unknown ingress types`() {
        val result = calculator.calculate(context(listOf("UNKNOWN")))
        assertEquals(config.exposureNonePoints, result.points)
    }

    @Test
    fun `should have exposure as category name`() {
        assertEquals("exposure", calculator.categoryName)
    }

    @Test
    fun `should have 25 as max points including automatable bonus`() {
        assertEquals(config.exposureExternalPoints + config.exposureAutomatableBonus, calculator.maxPoints)
    }
}
