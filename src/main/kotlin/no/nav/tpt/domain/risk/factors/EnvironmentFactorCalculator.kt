package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class EnvironmentFactorCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val (multiplier, isProduction) = getEnvironmentMultiplier(context.environment)

        return RiskFactor(
            name = "environment",
            value = multiplier,
            metadata = mapOf(
                "environment" to (context.environment ?: "unknown"),
                "isProduction" to isProduction
            )
        )
    }

    private fun getEnvironmentMultiplier(environment: String?): Pair<Double, Boolean> {
        if (environment == null) return 1.0 to false

        val isProduction = environment.startsWith("prod-", ignoreCase = true)
        val multiplier = if (isProduction) config.productionEnvironmentMultiplier else 1.0

        return multiplier to isProduction
    }
}

