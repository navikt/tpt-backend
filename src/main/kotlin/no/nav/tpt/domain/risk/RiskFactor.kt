package no.nav.tpt.domain.risk

data class RiskFactor(
    val name: String,
    val points: Int,
    val maxPoints: Int,
    val metadata: Map<String, Any> = emptyMap()
)


