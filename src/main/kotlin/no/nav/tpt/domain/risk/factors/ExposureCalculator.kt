package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class ExposureCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override val categoryName = "exposure"
    override val maxPoints = config.exposureExternalPoints + config.exposureAutomatableBonus

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val (basePoints, exposureType) = getExposurePoints(context.ingressTypes)
        val automatableBonus = if (context.ssvcAutomatable?.equals("yes", ignoreCase = true) == true)
            config.exposureAutomatableBonus else 0
        val totalPoints = minOf(basePoints + automatableBonus, maxPoints)

        return RiskFactor(
            name = categoryName,
            points = totalPoints,
            maxPoints = maxPoints,
            metadata = mapOf(
                "types" to context.ingressTypes,
                "exposureType" to exposureType,
                "automatable" to (context.ssvcAutomatable ?: "unknown"),
            )
        )
    }

    private fun getExposurePoints(ingressTypes: List<String>): Pair<Int, String> {
        val hasExternal = ingressTypes.any { it.equals("EXTERNAL", ignoreCase = true) }
        val hasAuthenticated = ingressTypes.any { it.equals("AUTHENTICATED", ignoreCase = true) }
        val hasInternal = ingressTypes.any { it.equals("INTERNAL", ignoreCase = true) }

        return when {
            hasExternal -> config.exposureExternalPoints to "external"
            hasAuthenticated -> config.exposureAuthenticatedPoints to "authenticated"
            hasInternal -> config.exposureInternalPoints to "internal"
            else -> config.exposureNonePoints to "none"
        }
    }
}
