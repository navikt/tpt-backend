package no.nav.tpt.domain.risk

import no.nav.tpt.domain.risk.factors.*

class DefaultRiskScorer(
    private val config: RiskScoringConfig = RiskScoringConfig()
) : RiskScorer {

    private val factorCalculators: List<FactorCalculator> = listOf(
        SeverityCalculator(config),
        ExploitationEvidenceCalculator(config),
        ExposureCalculator(config),
        EnvironmentCalculator(config),
        ActionabilityCalculator(config),
    )

    private val explanationGenerator = RiskExplanationGenerator(config)

    override fun calculateRiskScore(context: VulnerabilityRiskContext): RiskScoreResult {
        val factors = factorCalculators.map { it.calculate(context) }
        val rawScore = factors.sumOf { it.points }.toDouble()
        val finalScore = rawScore
            .let { if (context.suppressed) it * config.suppressedMultiplier else it }
            .let { if (context.vexNotAffected) it * config.vexNotAffectedMultiplier else it }

        val breakdown = explanationGenerator.generateBreakdown(
            factors, finalScore, context.suppressed, context.vexNotAffected
        )

        return RiskScoreResult(score = finalScore, breakdown = breakdown)
    }
}


