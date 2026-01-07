package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class EpssFactorCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val (multiplier, score) = getEpssMultiplierAndScore(context.epssScore)

        return RiskFactor(
            name = "epss",
            value = multiplier,
            metadata = buildMap {
                put("rawScore", context.epssScore ?: "unknown")
                score?.let { put("score", it) }
            }
        )
    }

    private fun getEpssMultiplierAndScore(epssScore: String?): Pair<Double, Double?> {
        if (epssScore == null) return 1.0 to null

        return try {
            val score = epssScore.toDouble()
            val multiplier = when {
                score >= 0.7 -> config.epssVeryHighMultiplier
                score >= 0.5 -> config.epssHighMultiplier
                score >= 0.3 -> config.epssMediumMultiplier
                score >= 0.1 -> config.epssLowMultiplier
                else -> 1.0
            }
            multiplier to score
        } catch (_: NumberFormatException) {
            1.0 to null
        }
    }
}

