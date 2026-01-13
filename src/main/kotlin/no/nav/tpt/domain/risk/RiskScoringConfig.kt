package no.nav.tpt.domain.risk

data class RiskScoringConfig(
    val criticalBaseScore: Double = 100.0,
    val highBaseScore: Double = 70.0,
    val mediumBaseScore: Double = 50.0,
    val lowBaseScore: Double = 20.0,
    val unknownBaseScore: Double = 10.0,

    val externalExposureMultiplier: Double = 2.0,
    val authenticatedExposureMultiplier: Double = 1.2,
    val internalExposureMultiplier: Double = 1.0,
    val noIngressMultiplier: Double = 0.5,

    val kevListedMultiplier: Double = 2.0,

    val epssVeryHighMultiplier: Double = 1.5,
    val epssHighMultiplier: Double = 1.3,
    val epssMediumMultiplier: Double = 1.2,
    val epssLowMultiplier: Double = 1.1,

    val suppressedMultiplier: Double = 0.3,

    val productionEnvironmentMultiplier: Double = 1.1,

    val oldBuildMultiplier: Double = 1.1,
    val oldBuildThresholdDays: Long = 90,

    val exploitReferenceMultiplier: Double = 1.3,
    val patchAvailableMultiplier: Double = 0.9
)

