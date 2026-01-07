package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class KevFactorCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val multiplier = if (context.hasKevEntry) config.kevListedMultiplier else 1.0

        return RiskFactor(
            name = "kev",
            value = multiplier,
            metadata = mapOf("listed" to context.hasKevEntry)
        )
    }
}

