package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class ActionabilityCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override val categoryName = "actionability"
    override val maxPoints = config.actionabilityPatchAvailablePoints + config.actionabilityRansomwarePoints

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val patchPoints = if (context.hasPatchReference) config.actionabilityPatchAvailablePoints else 0
        val ransomwarePoints = if (context.hasRansomwareCampaignUse) config.actionabilityRansomwarePoints else 0
        val noPatchPenalty = if (!context.hasPatchReference && !context.hasRansomwareCampaignUse)
            config.actionabilityNoPatchPenalty else 0
        val total = patchPoints + ransomwarePoints + noPatchPenalty

        return RiskFactor(
            name = categoryName,
            points = total,
            maxPoints = maxPoints,
            metadata = mapOf(
                "hasPatch" to context.hasPatchReference,
                "hasRansomwareCampaignUse" to context.hasRansomwareCampaignUse,
                "noPatchPenalty" to noPatchPenalty,
            )
        )
    }
}
