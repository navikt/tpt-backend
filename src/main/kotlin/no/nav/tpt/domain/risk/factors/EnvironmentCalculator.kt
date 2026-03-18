package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext
import java.time.LocalDate
import java.time.temporal.ChronoUnit

class EnvironmentCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override val categoryName = "environment"
    override val maxPoints = config.environmentProductionPoints +
            config.environmentOldBuildBonus +
            config.environmentChronicCveBonus

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val basePoints = getBaseEnvironmentPoints(context.environment)
        val hasIngress = context.ingressTypes.isNotEmpty()
        val buildAgeBonus = if (hasIngress) getBuildAgeBonus(context.buildDate) else 0
        val cveAgeBonus = if (hasIngress) getCveAgeBonus(context.cveDaysOld) else 0
        val total = basePoints + buildAgeBonus + cveAgeBonus

        return RiskFactor(
            name = categoryName,
            points = total,
            maxPoints = maxPoints,
            metadata = mapOf(
                "environment" to (context.environment ?: "unknown"),
                "basePoints" to basePoints,
                "buildAgeBonus" to buildAgeBonus,
                "cveAgeBonus" to cveAgeBonus,
                "ageBonusesSkipped" to (!hasIngress && (context.buildDate != null || context.cveDaysOld != null)),
            )
        )
    }

    private fun getBaseEnvironmentPoints(environment: String?): Int {
        if (environment == null) return config.environmentDevelopmentPoints
        return when {
            environment.equals("prod", ignoreCase = true) ||
                    environment.equals("production", ignoreCase = true) ||
                    environment.startsWith("prod-", ignoreCase = true) -> config.environmentProductionPoints
            environment.startsWith("staging", ignoreCase = true) ||
                    environment.startsWith("pre-prod", ignoreCase = true) -> config.environmentStagingPoints
            else -> config.environmentDevelopmentPoints
        }
    }

    private fun getBuildAgeBonus(buildDate: LocalDate?): Int {
        if (buildDate == null) return 0
        val daysOld = ChronoUnit.DAYS.between(buildDate, LocalDate.now())
        return if (daysOld > config.environmentOldBuildThresholdDays) config.environmentOldBuildBonus else 0
    }

    private fun getCveAgeBonus(cveDaysOld: Long?): Int {
        if (cveDaysOld == null) return 0
        return if (cveDaysOld > config.environmentChronicCveThresholdDays) config.environmentChronicCveBonus else 0
    }
}
