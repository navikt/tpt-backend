package no.nav.tpt.domain.risk

class RiskExplanationGenerator(private val config: RiskScoringConfig) {

    fun generateBreakdown(
        baseScore: Double,
        factors: List<RiskFactor>,
        finalScore: Double
    ): RiskScoreBreakdown {
        val explanations = factors
            .filter { factor -> factor.value != 1.0 }
            .map { factor ->
                val contribution = calculateContribution(baseScore, factor, factors)
                val percentage = if (finalScore > 0) (contribution / finalScore) * 100 else 0.0

                RiskFactorExplanation(
                    name = factor.name,
                    contribution = contribution,
                    percentage = percentage,
                    explanation = generateExplanation(factor),
                    impact = determineImpact(factor.value, factor.name)
                )
            }
            .sortedByDescending { kotlin.math.abs(it.contribution) }

        return RiskScoreBreakdown(
            baseScore = baseScore,
            factors = explanations,
            totalScore = finalScore
        )
    }

    private fun calculateContribution(baseScore: Double, factor: RiskFactor, allFactors: List<RiskFactor>): Double {
        val otherMultipliers = allFactors
            .filter { it.name != factor.name }
            .map { it.value }
            .fold(1.0) { acc, v -> acc * v }
        val scoreWithFactor = baseScore * otherMultipliers * factor.value
        val scoreWithoutFactor = baseScore * otherMultipliers
        return scoreWithFactor - scoreWithoutFactor
    }

    private fun generateExplanation(factor: RiskFactor): String = when (factor.name) {
        "exposure" -> {
            val exposureType = factor.metadata["exposureType"] as? String ?: "unknown"
            when (exposureType) {
                "external" -> "Application is externally accessible"
                "authenticated" -> "Application requires authentication"
                "internal" -> "Application is only internally accessible"
                "none" -> "Application has no ingress (reduced exposure)"
                else -> "Unknown exposure type"
            }
        }
        "kev" -> {
            val listed = factor.metadata["listed"] as? Boolean ?: false
            if (listed) "Known exploited vulnerability (CISA KEV)" else "Not in CISA KEV database"
        }
        "epss" -> {
            val score = factor.metadata["score"] as? Double
            if (score != null) {
                val percentage = (score * 100).toInt()
                "Exploit probability: $percentage% (EPSS)"
            } else {
                "EPSS score unavailable"
            }
        }
        "suppression" -> {
            val suppressed = factor.metadata["suppressed"] as? Boolean ?: false
            if (suppressed) "Vulnerability marked as suppressed" else "Vulnerability is active"
        }
        "environment" -> {
            val isProduction = factor.metadata["isProduction"] as? Boolean ?: false
            if (isProduction) "Running in production environment" else "Running in non-production environment"
        }
        "build_age" -> {
            val daysOld = factor.metadata["daysOld"] as? Long
            if (daysOld != null && daysOld > config.oldBuildThresholdDays) {
                "Build is $daysOld days old (over ${config.oldBuildThresholdDays} day threshold)"
            } else {
                "Build is recent"
            }
        }
        "exploit_reference" -> {
            val hasExploit = factor.metadata["hasExploit"] as? Boolean ?: false
            if (hasExploit) "Exploit code publicly available" else "No known exploit code"
        }
        "patch_available" -> {
            val hasPatch = factor.metadata["hasPatch"] as? Boolean ?: false
            if (hasPatch) "Patch is available" else "No patch information"
        }
        else -> factor.name
    }

    // Values >1.0 increase risk, <1.0 mitigate risk (both significant for scoring)
    private fun determineImpact(value: Double, name: String): ImpactLevel {
        if (name == "suppression" && value < 1.0) return ImpactLevel.HIGH

        return when {
            value >= 2.0 -> ImpactLevel.CRITICAL
            value >= 1.5 -> ImpactLevel.HIGH
            value >= 1.2 -> ImpactLevel.MEDIUM
            value > 1.0 -> ImpactLevel.LOW
            value < 1.0 -> ImpactLevel.MEDIUM
            else -> ImpactLevel.NONE
        }
    }
}

