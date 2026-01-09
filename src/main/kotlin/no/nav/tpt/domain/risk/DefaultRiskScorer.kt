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

        val multipliers = buildMultipliersMap(context.severity, baseScore, factors)
        val breakdown = explanationGenerator.generateBreakdown(baseScore, factors, finalScore)

        return RiskScoreResult(score = finalScore, multipliers = multipliers, breakdown = breakdown)
    }

    private fun buildMultipliersMap(
        severity: String,
        baseScore: Double,
        factors: List<RiskFactor>
    ): Map<String, Double> {
        val multipliers = mutableMapOf<String, Double>()
        multipliers["severity"] = baseScore

        factors.forEach { factor ->
            when (factor.name) {
                "exposure" -> {
                    if (factor.value != 1.0) multipliers["exposure"] = factor.value
                }
                "kev" -> {
                    if (factor.value != 1.0) multipliers["kev"] = factor.value
                }
                "epss" -> {
                    val score = factor.metadata["score"] as? Double
                    if (score != null && score >= 0.1 && factor.value != 1.0) {
                        multipliers["epss"] = factor.value
                    }
                }
                "suppression" -> {
                    val suppressed = factor.metadata["suppressed"] as? Boolean ?: false
                    if (suppressed) multipliers["suppressed"] = factor.value
                }
                "environment" -> {
                    if (factor.value != 1.0) multipliers["production"] = factor.value
                }
                "build_age" -> {
                    val daysOld = factor.metadata["daysOld"] as? Long
                    if (daysOld != null && daysOld > config.oldBuildThresholdDays && factor.value != 1.0) {
                        multipliers["old_build_days"] = daysOld.toDouble()
                        multipliers["old_build"] = factor.value
                    }
                }
                "exploit_reference" -> {
                    if (factor.value != 1.0) multipliers["exploit_reference"] = factor.value
                }
                "patch_available" -> {
                    if (factor.value != 1.0) multipliers["patch_available"] = factor.value
                }
            }
        }

        return multipliers
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

