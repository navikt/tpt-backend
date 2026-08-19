package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.FactorCalculator
import no.nav.tpt.domain.risk.RiskFactor
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext

class SeverityCalculator(private val config: RiskScoringConfig) : FactorCalculator {

    override val categoryName = "severity"
    override val maxPoints = config.severityCriticalPoints

    override fun calculate(context: VulnerabilityRiskContext): RiskFactor {
        val normalized = normalizeSeverity(context.severity.uppercase())
        val points = when (normalized) {
            "CRITICAL" -> config.severityCriticalPoints
            "HIGH" -> config.severityHighPoints
            "MEDIUM" -> config.severityMediumPoints
            "LOW" -> config.severityLowPoints
            else -> config.severityUnknownPoints
        }

        return RiskFactor(
            name = categoryName,
            points = points,
            maxPoints = maxPoints,
            metadata = mapOf("severity" to normalized)
        )
    }

    // Maps vendor-specific severity labels to CVSS standard terms.
    // GitHub Advisory uses MODERATE instead of MEDIUM.
    private fun normalizeSeverity(severity: String): String = when (severity) {
        "MODERATE" -> "MEDIUM"
        else -> severity
    }
}
