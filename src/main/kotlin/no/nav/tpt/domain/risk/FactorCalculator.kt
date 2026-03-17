package no.nav.tpt.domain.risk

interface FactorCalculator {
    val categoryName: String
    val maxPoints: Int
    fun calculate(context: VulnerabilityRiskContext): RiskFactor
}

