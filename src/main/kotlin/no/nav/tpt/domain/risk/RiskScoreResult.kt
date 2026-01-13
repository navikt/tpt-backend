package no.nav.tpt.domain.risk

import kotlinx.serialization.Serializable

@Serializable
data class RiskScoreResult(
    val score: Double,
    val breakdown: RiskScoreBreakdown? = null
)

@Serializable
data class RiskScoreBreakdown(
    val baseScore: Double,
    val factors: List<RiskFactorExplanation>,
    val totalScore: Double
)

@Serializable
data class RiskFactorExplanation(
    val name: String,
    val contribution: Double,
    val explanation: String,
    val impact: ImpactLevel,
    val multiplier: Double
)

enum class ImpactLevel {
    CRITICAL, HIGH, MEDIUM, LOW, NONE
}