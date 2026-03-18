package no.nav.tpt.domain.risk

class RiskExplanationGenerator(private val config: RiskScoringConfig) {

    fun generateBreakdown(factors: List<RiskFactor>, totalScore: Double, suppressed: Boolean = false): RiskScoreBreakdown {
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
            suppressed = suppressed,
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
            val ssvc = factor.metadata["ssvcExploitation"] as? String
            when {
                ssvc?.equals("active", ignoreCase = true) == true ->
                    "Active exploitation confirmed (SSVC/Vulnrichment)"
                hasKev -> "Active exploitation confirmed (CISA KEV)"
                ssvc?.equals("poc", ignoreCase = true) == true ->
                    "Exploit PoC confirmed (SSVC/Vulnrichment)"
                hasPoc && epss != null && epss != "unknown" ->
                    "Exploit PoC available, EPSS: $epss"
                hasPoc -> "Exploit PoC available"
                epss != null && epss != "unknown" -> "Exploit probability: $epss (EPSS)"
                else -> "No exploitation evidence found"
            }
        }
        "exposure" -> {
            val exposureType = factor.metadata["exposureType"] as? String ?: "unknown"
            val automatable = factor.metadata["automatable"] as? String
            val automatableSuffix = if (automatable?.equals("yes", ignoreCase = true) == true)
                " (automatable: exploit chain can be scripted)" else ""
            when (exposureType) {
                "external" -> "Application is externally accessible$automatableSuffix"
                "authenticated" -> "Application requires authentication$automatableSuffix"
                "internal" -> "Application is only internally accessible$automatableSuffix"
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
                if (buildAgeBonus > 0) append(", build age >${config.environmentOldBuildThresholdDays} days (+$buildAgeBonus)")
                if (cveAgeBonus > 0) append(", CVE age >${config.environmentChronicCveThresholdDays} days (+$cveAgeBonus)")
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


