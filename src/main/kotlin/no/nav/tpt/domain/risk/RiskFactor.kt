package no.nav.tpt.domain.risk

data class RiskFactor(
    val name: String,
    val value: Double,
    val metadata: Map<String, Any> = emptyMap()
)


