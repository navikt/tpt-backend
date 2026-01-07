package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class PatchAvailableFactorCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val multiplier = if (context.hasPatchReference) config.patchAvailableMultiplier else 1.0

        return RiskFactor(
            name = "patch_available",
            value = multiplier,
            metadata = mapOf("hasPatch" to context.hasPatchReference)
        )
    }
}

