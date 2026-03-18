package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext
import kotlin.test.Test
import kotlin.test.assertEquals

class SeverityCalculatorTest {

    private val config = RiskScoringConfig()
    private val calculator = SeverityCalculator(config)

    private fun context(severity: String) = VulnerabilityRiskContext(
        severity = severity, ingressTypes = emptyList(),
        hasKevEntry = false, epssScore = null, suppressed = false,
        environment = null, buildDate = null,
    )

    @Test
    fun `should return 25 points for CRITICAL severity`() {
        val result = calculator.calculate(context("CRITICAL"))
        assertEquals(config.severityCriticalPoints, result.points)
        assertEquals(config.severityCriticalPoints, result.maxPoints)
    }

    @Test
    fun `should return 18 points for HIGH severity`() {
        val result = calculator.calculate(context("HIGH"))
        assertEquals(config.severityHighPoints, result.points)
    }

    @Test
    fun `should return 12 points for MEDIUM severity`() {
        val result = calculator.calculate(context("MEDIUM"))
        assertEquals(config.severityMediumPoints, result.points)
    }

    @Test
    fun `should return 5 points for LOW severity`() {
        val result = calculator.calculate(context("LOW"))
        assertEquals(config.severityLowPoints, result.points)
    }

    @Test
    fun `should return 2 points for UNKNOWN severity`() {
        val result = calculator.calculate(context("UNKNOWN"))
        assertEquals(config.severityUnknownPoints, result.points)
    }

    @Test
    fun `should return unknown points for unrecognized severity`() {
        val result = calculator.calculate(context("BOGUS"))
        assertEquals(config.severityUnknownPoints, result.points)
    }

    @Test
    fun `should be case insensitive`() {
        assertEquals(
            calculator.calculate(context("CRITICAL")).points,
            calculator.calculate(context("critical")).points
        )
    }

    @Test
    fun `should have severity as category name`() {
        assertEquals("severity", calculator.categoryName)
    }
}
