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
}

