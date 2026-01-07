package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext
import java.time.LocalDate
import java.time.temporal.ChronoUnit

class BuildAgeFactorCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val (multiplier, daysOld) = getBuildAgeMultiplier(context.buildDate)

        return RiskFactor(
            name = "build_age",
            value = multiplier,
            metadata = buildMap {
                put("buildDate", context.buildDate?.toString() ?: "unknown")
                daysOld?.let { put("daysOld", it) }
            }
        )
    }

    private fun getBuildAgeMultiplier(buildDate: LocalDate?): Pair<Double, Long?> {
        if (buildDate == null) return 1.0 to null

        val daysOld = ChronoUnit.DAYS.between(buildDate, LocalDate.now())
        val multiplier = if (daysOld > config.oldBuildThresholdDays) config.oldBuildMultiplier else 1.0

        return multiplier to daysOld
    }
}

