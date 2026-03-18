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
            "Base severity: $severity"
        }
        "exploitation_evidence" -> {
            val hasKev = factor.metadata["hasKevEntry"] as? Boolean ?: false
            val epssRaw = factor.metadata["epssScore"] as? String
            val hasPoc = factor.metadata["hasExploitReference"] as? Boolean ?: false
            val ssvc = factor.metadata["ssvcExploitation"] as? String
            val epssExplanation = formatEpssExplanation(epssRaw)
            when {
                ssvc?.equals("active", ignoreCase = true) == true ->
                    "Active exploitation confirmed (SSVC/Vulnrichment)"
                hasKev -> "Active exploitation confirmed (CISA KEV)"
                ssvc?.equals("poc", ignoreCase = true) == true ->
                    "Exploit PoC confirmed (SSVC/Vulnrichment)"
                hasPoc && epssExplanation != null ->
                    "Exploit PoC available — $epssExplanation"
                hasPoc -> "Exploit PoC available"
                epssExplanation != null -> epssExplanation
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
            val ageBonusesSkipped = factor.metadata["ageBonusesSkipped"] as? Boolean ?: false
            buildString {
                append("Environment: $env")
                if (buildAgeBonus > 0) append(", build age >${config.environmentOldBuildThresholdDays} days (+$buildAgeBonus)")
                if (cveAgeBonus > 0) append(", CVE age >${config.environmentChronicCveThresholdDays} days (+$cveAgeBonus)")
                if (ageBonusesSkipped) append(" (age bonuses skipped — no network exposure)")
            }
        }
        "actionability" -> {
            val hasPatch = factor.metadata["hasPatch"] as? Boolean ?: false
            val hasRansomware = factor.metadata["hasRansomwareCampaignUse"] as? Boolean ?: false
            val penalty = factor.metadata["noPatchPenalty"] as? Int ?: 0
            val penaltySuffix = if (penalty < 0) " (no fix available — deprioritized)" else ""
            when {
                hasPatch && hasRansomware -> "Patch available; linked to ransomware campaigns"
                hasPatch -> "Patch is available"
                hasRansomware -> "Linked to known ransomware campaigns"
                else -> "No patch or ransomware data$penaltySuffix"
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

    private fun formatEpssExplanation(epssRaw: String?): String? {
        if (epssRaw == null || epssRaw == "unknown") return null
        val score = epssRaw.toDoubleOrNull() ?: return null
        val percentage = score * 100
        val formatted = if (percentage >= 1.0) {
            "%.1f%%".format(percentage)
        } else {
            "%.2f%%".format(percentage)
        }
        val label = when {
            score >= config.epssVeryHighThreshold -> "very high likelihood of exploitation"
            score >= config.epssHighThreshold -> "high likelihood of exploitation"
            score >= config.epssMediumThreshold -> "moderate likelihood of exploitation"
            score >= config.epssLowThreshold -> "low likelihood of exploitation"
            else -> "minimal likelihood of exploitation"
        }
        return "EPSS $formatted — $label"
    }
}


