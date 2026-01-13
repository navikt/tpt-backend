package no.nav.tpt.domain.risk

import no.nav.tpt.domain.risk.factors.*

class DefaultRiskScorer(
    private val config: RiskScoringConfig = RiskScoringConfig()
) : RiskScorer {

    private val factorCalculators: List<FactorCalculator> = listOf(
        ExposureFactorCalculator(config),
        KevFactorCalculator(config),
        EpssFactorCalculator(config),
        SuppressionFactorCalculator(config),
        EnvironmentFactorCalculator(config),
        BuildAgeFactorCalculator(config),
        ExploitReferenceFactorCalculator(config),
        PatchAvailableFactorCalculator(config)
    )

    private val explanationGenerator = RiskExplanationGenerator(config)

    override fun calculateRiskScore(context: VulnerabilityRiskContext): RiskScoreResult {
        val baseScore = getBaseSeverityScore(context.severity)
        val factors = factorCalculators.map { it.calculate(context) }
        val combinedMultiplier = factors.map { it.value }.fold(1.0) { acc, value -> acc * value }
        val finalScore = baseScore * combinedMultiplier

        val breakdown = explanationGenerator.generateBreakdown(context.severity, baseScore, factors, finalScore)

        return RiskScoreResult(score = finalScore, breakdown = breakdown)
    }

    private fun getBaseSeverityScore(severity: String): Double {
        return when (severity.uppercase()) {
            "CRITICAL" -> config.criticalBaseScore
            "HIGH" -> config.highBaseScore
            "MEDIUM" -> config.mediumBaseScore
            "LOW" -> config.lowBaseScore
            else -> config.unknownBaseScore
        }
    }
}

