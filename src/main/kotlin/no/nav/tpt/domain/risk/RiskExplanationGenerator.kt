package no.nav.tpt.domain.risk

class RiskExplanationGenerator(private val config: RiskScoringConfig) {

    fun generateBreakdown(factors: List<RiskFactor>, totalScore: Double): RiskScoreBreakdown {
        val explanations = factors
            .sortedByDescending { it.points }
            .map { factor ->
                RiskFactorExplanation(
                    name = factor.name,
                    points = factor.points,
                    maxPoints = factor.maxPoints,
                    explanation = generateExplanation(factor),
                    impact = determineImpact(factor.points, factor.maxPoints),
                )
            }

        return RiskScoreBreakdown(
            totalScore = totalScore,
            factors = explanations,
        )
    }

    private fun generateExplanation(factor: RiskFactor): String = when (factor.name) {
        "severity" -> {
            val severity = factor.metadata["severity"] as? String ?: "unknown"
            "Base severity: $severity (${factor.points}/${factor.maxPoints} points)"
        }
        "exploitation_evidence" -> {
            val hasKev = factor.metadata["hasKevEntry"] as? Boolean ?: false
            val epss = factor.metadata["epssScore"] as? String
            val hasPoc = factor.metadata["hasExploitReference"] as? Boolean ?: false
            when {
                hasKev -> "Active exploitation confirmed (CISA KEV)"
                hasPoc && epss != null && epss != "unknown" ->
                    "Exploit PoC available, EPSS: $epss"
                hasPoc -> "Exploit PoC available"
                epss != null && epss != "unknown" -> "Exploit probability: $epss (EPSS)"
                else -> "No exploitation evidence found"
            }
        }
        "exposure" -> {
            val exposureType = factor.metadata["exposureType"] as? String ?: "unknown"
            when (exposureType) {
                "external" -> "Application is externally accessible"
                "authenticated" -> "Application requires authentication"
                "internal" -> "Application is only internally accessible"
                "none" -> "Application has no ingress"
                else -> "Unknown exposure type"
            }
        }
        "environment" -> {
            val env = factor.metadata["environment"] as? String ?: "unknown"
            val buildAgeBonus = factor.metadata["buildAgeBonus"] as? Int ?: 0
            val cveAgeBonus = factor.metadata["cveAgeBonus"] as? Int ?: 0
            buildString {
                append("Environment: $env")
                if (buildAgeBonus > 0) append(", build age >90 days (+$buildAgeBonus)")
                if (cveAgeBonus > 0) append(", CVE age >365 days (+$cveAgeBonus)")
            }
        }
        "actionability" -> {
            val hasPatch = factor.metadata["hasPatch"] as? Boolean ?: false
            val hasRansomware = factor.metadata["hasRansomwareCampaignUse"] as? Boolean ?: false
            when {
                hasPatch && hasRansomware -> "Patch available; linked to ransomware campaigns"
                hasPatch -> "Patch is available"
                hasRansomware -> "Linked to known ransomware campaigns"
                else -> "No patch or ransomware data"
            }
        }
        else -> factor.name
    }

    private fun determineImpact(points: Int, maxPoints: Int): ImpactLevel {
        if (maxPoints == 0) return ImpactLevel.NONE
        val ratio = points.toDouble() / maxPoints
        return when {
            ratio >= 0.9 -> ImpactLevel.CRITICAL
            ratio >= 0.6 -> ImpactLevel.HIGH
            ratio >= 0.3 -> ImpactLevel.MEDIUM
            ratio > 0.0 -> ImpactLevel.LOW
            else -> ImpactLevel.NONE
        }
    }
}


