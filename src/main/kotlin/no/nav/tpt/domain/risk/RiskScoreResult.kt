package no.nav.tpt.domain.risk

import kotlinx.serialization.Serializable

@Serializable
data class RiskScoreResult(
    val score: Double,
    val breakdown: RiskScoreBreakdown? = null
)

@Serializable
data class RiskScoreBreakdown(
    val totalScore: Double,
    val factors: List<RiskFactorExplanation>,
)

@Serializable
data class RiskFactorExplanation(
    val name: String,
    val points: Int,
    val maxPoints: Int,
    val explanation: String,
    val impact: ImpactLevel,
)

enum class ImpactLevel {
    CRITICAL, HIGH, MEDIUM, LOW, NONE
}