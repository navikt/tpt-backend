package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class ExposureFactorCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val (multiplier, exposureType) = getExposureMultiplierAndType(context.ingressTypes)

        return RiskFactor(
            name = "exposure",
            value = multiplier,
            metadata = mapOf(
                "types" to context.ingressTypes,
                "exposureType" to exposureType
            )
        )
    }

    private fun getExposureMultiplierAndType(ingressTypes: List<String>): Pair<Double, String> {
        if (ingressTypes.isEmpty()) {
            return config.noIngressMultiplier to "none"
        }

        val hasExternal = ingressTypes.any { it.equals("EXTERNAL", ignoreCase = true) }
        val hasAuthenticated = ingressTypes.any { it.equals("AUTHENTICATED", ignoreCase = true) }
        val hasInternal = ingressTypes.any { it.equals("INTERNAL", ignoreCase = true) }

        return when {
            hasExternal -> config.externalExposureMultiplier to "external"
            hasAuthenticated -> config.authenticatedExposureMultiplier to "authenticated"
            hasInternal -> config.internalExposureMultiplier to "internal"
            else -> config.noIngressMultiplier to "none"
        }
    }
}

