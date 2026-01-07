package no.nav.tpt.domain.risk

interface FactorCalculator {
    fun calculate(context: VulnerabilityRiskContext): RiskFactor
}

