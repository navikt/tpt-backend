package no.nav.tpt.domain.risk

data class RiskScoringConfig(
    // Category 1: Severity points (max 25)
    val severityCriticalPoints: Int = 25,
    val severityHighPoints: Int = 18,
    val severityMediumPoints: Int = 12,
    val severityLowPoints: Int = 5,
    val severityUnknownPoints: Int = 2,

    // Category 2: Exploitation evidence points (max 30)
    val exploitationActivePoints: Int = 30,          // KEV listed OR Vulnrichment active
    val exploitationPocHighEpssPoints: Int = 25,     // exploit PoC + EPSS >= 0.5
    val exploitationKevLowEpssPoints: Int = 25,      // KEV alone (EPSS < threshold)
    val exploitationEpssVeryHighPoints: Int = 22,    // EPSS >= 0.7, no PoC
    val exploitationPocOnlyPoints: Int = 18,         // exploit PoC, no KEV, low EPSS
    val exploitationEpssHighPoints: Int = 15,        // EPSS 0.5–0.7, no PoC
    val exploitationEpssMediumPoints: Int = 10,      // EPSS 0.3–0.5
    val exploitationEpssLowPoints: Int = 5,          // EPSS 0.1–0.3

    // EPSS thresholds for exploitation category
    val epssVeryHighThreshold: Double = 0.7,
    val epssHighThreshold: Double = 0.5,
    val epssMediumThreshold: Double = 0.3,
    val epssLowThreshold: Double = 0.1,

    // Category 3: Exposure points (max 20, +5 bonus for automatable)
    val exposureExternalPoints: Int = 20,
    val exposureAuthenticatedPoints: Int = 12,
    val exposureInternalPoints: Int = 5,
    val exposureNonePoints: Int = 0,
    val exposureAutomatableBonus: Int = 5,           // Vulnrichment: automatable=yes

    // Category 4: Environment context points (max 15)
    val environmentProductionPoints: Int = 10,
    val environmentStagingPoints: Int = 5,
    val environmentDevelopmentPoints: Int = 0,
    val environmentOldBuildBonus: Int = 3,           // build age > threshold days
    val environmentOldBuildThresholdDays: Long = 90,
    val environmentChronicCveBonus: Int = 2,         // CVE age > threshold days
    val environmentChronicCveThresholdDays: Long = 365,

    // Category 5: Actionability & urgency points (max 10)
    val actionabilityPatchAvailablePoints: Int = 5,
    val actionabilityRansomwarePoints: Int = 5,

    // Suppression: multiplier applied to total score after all categories
    val suppressedMultiplier: Double = 0.2,
)

