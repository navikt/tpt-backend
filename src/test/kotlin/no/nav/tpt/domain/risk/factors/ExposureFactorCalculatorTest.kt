package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext
import kotlin.test.Test
import kotlin.test.assertEquals

class ExposureFactorCalculatorTest {

    private val config = RiskScoringConfig()
    private val calculator = ExposureFactorCalculator(config)

    @Test
    fun `should prioritize EXTERNAL when application has multiple ingress types`() {
        val context = VulnerabilityRiskContext(
            severity = "CRITICAL",
            ingressTypes = listOf("INTERNAL", "AUTHENTICATED", "EXTERNAL"),
            hasKevEntry = false,
            epssScore = null,
            suppressed = false,
            environment = null,
            buildDate = null
        )

        val result = calculator.calculate(context)

        assertEquals("exposure", result.name)
        assertEquals(config.externalExposureMultiplier, result.value)
        assertEquals("external", result.metadata["exposureType"])
    }

    @Test
    fun `should prioritize AUTHENTICATED when application has AUTHENTICATED and INTERNAL`() {
        val context = VulnerabilityRiskContext(
            severity = "CRITICAL",
            ingressTypes = listOf("INTERNAL", "AUTHENTICATED"),
            hasKevEntry = false,
            epssScore = null,
            suppressed = false,
            environment = null,
            buildDate = null
        )

        val result = calculator.calculate(context)

        assertEquals("exposure", result.name)
        assertEquals(config.authenticatedExposureMultiplier, result.value)
        assertEquals("authenticated", result.metadata["exposureType"])
    }

    @Test
    fun `should prioritize INTERNAL when application has INTERNAL and UNKNOWN`() {
        val context = VulnerabilityRiskContext(
            severity = "CRITICAL",
            ingressTypes = listOf("UNKNOWN", "INTERNAL"),
            hasKevEntry = false,
            epssScore = null,
            suppressed = false,
            environment = null,
            buildDate = null
        )

        val result = calculator.calculate(context)

        assertEquals("exposure", result.name)
        assertEquals(config.internalExposureMultiplier, result.value)
        assertEquals("internal", result.metadata["exposureType"])
    }

    @Test
    fun `should use UNKNOWN when application has only UNKNOWN ingress types`() {
        val context = VulnerabilityRiskContext(
            severity = "CRITICAL",
            ingressTypes = listOf("UNKNOWN"),
            hasKevEntry = false,
            epssScore = null,
            suppressed = false,
            environment = null,
            buildDate = null
        )

        val result = calculator.calculate(context)

        assertEquals("exposure", result.name)
        assertEquals(config.noIngressMultiplier, result.value)
        assertEquals("none", result.metadata["exposureType"])
    }

    @Test
    fun `should prioritize EXTERNAL regardless of order in list`() {
        val context = VulnerabilityRiskContext(
            severity = "CRITICAL",
            ingressTypes = listOf("AUTHENTICATED", "INTERNAL", "EXTERNAL", "UNKNOWN"),
            hasKevEntry = false,
            epssScore = null,
            suppressed = false,
            environment = null,
            buildDate = null
        )

        val result = calculator.calculate(context)

        assertEquals("exposure", result.name)
        assertEquals(config.externalExposureMultiplier, result.value)
        assertEquals("external", result.metadata["exposureType"])
    }

    @Test
    fun `should handle empty ingress types list`() {
        val context = VulnerabilityRiskContext(
            severity = "CRITICAL",
            ingressTypes = emptyList(),
            hasKevEntry = false,
            epssScore = null,
            suppressed = false,
            environment = null,
            buildDate = null
        )

        val result = calculator.calculate(context)

        assertEquals("exposure", result.name)
        assertEquals(config.noIngressMultiplier, result.value)
        assertEquals("none", result.metadata["exposureType"])
    }
}

