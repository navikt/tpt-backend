package no.nav.tpt.domain.risk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNotEquals

class RiskExplanationGeneratorTest {

    private val config = RiskScoringConfig()
    private val generator = RiskExplanationGenerator(config)

    private fun severityFactor(points: Int) = RiskFactor(
        name = "severity",
        points = points,
        maxPoints = config.severityCriticalPoints,
        metadata = mapOf("severity" to "HIGH")
    )

    private fun exploitationFactor(points: Int) = RiskFactor(
        name = "exploitation_evidence",
        points = points,
        maxPoints = config.exploitationActivePoints,
        metadata = mapOf("hasKevEntry" to true, "epssScore" to "0.5")
    )

    private fun exposureFactor(points: Int) = RiskFactor(
        name = "exposure",
        points = points,
        maxPoints = config.exposureExternalPoints,
        metadata = mapOf("exposureType" to "external")
    )

    private fun environmentFactor(points: Int) = RiskFactor(
        name = "environment",
        points = points,
        maxPoints = config.environmentProductionPoints,
        metadata = mapOf("environment" to "prod", "buildAgeBonus" to 0, "cveAgeBonus" to 0)
    )

    private fun actionabilityFactor(points: Int) = RiskFactor(
        name = "actionability",
        points = points,
        maxPoints = config.actionabilityPatchAvailablePoints + config.actionabilityRansomwarePoints,
        metadata = mapOf("hasPatch" to true, "hasRansomwareCampaignUse" to false)
    )

    @Test
    fun `should have explanation for each risk factor`() {
        val factors = listOf(
            severityFactor(18),
            exploitationFactor(30),
            exposureFactor(20),
            environmentFactor(10),
            actionabilityFactor(5)
        )
        val totalScore = factors.sumOf { it.points }.toDouble()
        val breakdown = generator.generateBreakdown(factors, totalScore)

        assertEquals(5, breakdown.factors.size)
        breakdown.factors.forEach { explanation ->
            assertNotEquals(explanation.name, explanation.explanation,
                "Factor '${explanation.name}' should have a proper explanation, not just the factor name")
        }
    }

    @Test
    fun `should calculate correct total score in breakdown`() {
        val factors = listOf(
            severityFactor(18),
            exploitationFactor(30),
            exposureFactor(20),
            environmentFactor(10),
            actionabilityFactor(5)
        )
        val totalScore = 83.0
        val breakdown = generator.generateBreakdown(factors, totalScore)

        assertEquals(totalScore, breakdown.totalScore)
    }

    @Test
    fun `should include points and maxPoints for each factor`() {
        val factors = listOf(
            severityFactor(18),
            exposureFactor(20)
        )
        val breakdown = generator.generateBreakdown(factors, 38.0)

        val severityExplanation = breakdown.factors.find { it.name == "severity" }
        assertNotNull(severityExplanation)
        assertEquals(18, severityExplanation.points)
        assertEquals(config.severityCriticalPoints, severityExplanation.maxPoints)

        val exposureExplanation = breakdown.factors.find { it.name == "exposure" }
        assertNotNull(exposureExplanation)
        assertEquals(20, exposureExplanation.points)
        assertEquals(config.exposureExternalPoints, exposureExplanation.maxPoints)
    }

    @Test
    fun `should sort factors by points descending`() {
        val factors = listOf(
            environmentFactor(10),
            severityFactor(18),
            exploitationFactor(30)
        )
        val breakdown = generator.generateBreakdown(factors, 58.0)

        val points = breakdown.factors.map { it.points }
        assertEquals(points, points.sortedDescending())
    }

    @Test
    fun `should mention SSVC active exploitation in explanation`() {
        val factor = RiskFactor(
            name = "exploitation_evidence",
            points = 30,
            maxPoints = config.exploitationActivePoints,
            metadata = mapOf(
                "hasKevEntry" to false,
                "epssScore" to "unknown",
                "hasExploitReference" to false,
                "ssvcExploitation" to "active",
            )
        )
        val breakdown = generator.generateBreakdown(listOf(factor), 30.0)
        val explanation = breakdown.factors.first().explanation
        assert(explanation.contains("SSVC") || explanation.contains("active")) {
            "Expected explanation to mention SSVC/active exploitation, got: $explanation"
        }
    }

    @Test
    fun `should mention SSVC poc exploitation in explanation`() {
        val factor = RiskFactor(
            name = "exploitation_evidence",
            points = 18,
            maxPoints = config.exploitationActivePoints,
            metadata = mapOf(
                "hasKevEntry" to false,
                "epssScore" to "unknown",
                "hasExploitReference" to false,
                "ssvcExploitation" to "poc",
            )
        )
        val breakdown = generator.generateBreakdown(listOf(factor), 18.0)
        val explanation = breakdown.factors.first().explanation
        assert(explanation.contains("PoC") || explanation.contains("poc") || explanation.contains("SSVC")) {
            "Expected explanation to mention PoC/SSVC, got: $explanation"
        }
    }

    @Test
    fun `should mention automatable bonus in exposure explanation`() {
        val factor = RiskFactor(
            name = "exposure",
            points = 25,
            maxPoints = config.exposureExternalPoints + config.exposureAutomatableBonus,
            metadata = mapOf(
                "exposureType" to "external",
                "automatable" to "yes",
            )
        )
        val breakdown = generator.generateBreakdown(listOf(factor), 25.0)
        val explanation = breakdown.factors.first().explanation
        assert(explanation.contains("automatable") || explanation.contains("Automatable")) {
            "Expected explanation to mention automatable bonus, got: $explanation"
        }
    }

    @Test
    fun `should not mention automatable when not applicable`() {
        val factor = RiskFactor(
            name = "exposure",
            points = 20,
            maxPoints = config.exposureExternalPoints + config.exposureAutomatableBonus,
            metadata = mapOf(
                "exposureType" to "external",
                "automatable" to "no",
            )
        )
        val breakdown = generator.generateBreakdown(listOf(factor), 20.0)
        val explanation = breakdown.factors.first().explanation
        assert(!explanation.contains("automatable") && !explanation.contains("Automatable")) {
            "Expected explanation NOT to mention automatable when no bonus, got: $explanation"
        }
    }
}

