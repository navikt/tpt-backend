package no.nav.tpt.domain

import kotlinx.serialization.Serializable

@Serializable
data class ConfigResponse(
    val thresholds: RiskThresholds,
    val aiEnabled: Boolean
)

@Serializable
data class RiskThresholds(
    val high: Double,
    val medium: Double,
    val low: Double
)

