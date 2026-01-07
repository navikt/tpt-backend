package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class SuppressionFactorCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val multiplier = if (context.suppressed) config.suppressedMultiplier else 1.0

        return RiskFactor(
            name = "suppression",
            value = multiplier,
            metadata = mapOf("suppressed" to context.suppressed)
        )
    }
}

