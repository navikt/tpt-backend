package no.nav.tpt.domain

import kotlinx.serialization.Serializable

@Serializable
data class ConfigResponse(
    val thresholds: RiskThresholds,
    val scoring: RiskScoringCategories,
    val aiEnabled: Boolean
)

@Serializable
data class RiskThresholds(
    val high: Double,
    val medium: Double,
    val low: Double
)

@Serializable
data class RiskScoringCategories(
    val severityMax: Int,
    val exploitationMax: Int,
    val exposureMax: Int,
    val environmentMax: Int,
    val actionabilityMax: Int,
)

