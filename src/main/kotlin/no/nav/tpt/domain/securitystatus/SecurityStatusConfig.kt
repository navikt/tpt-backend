package no.nav.tpt.domain.securitystatus

data class SecurityStatusConfig(
    val deployMaxAgeDays: Long = 60,
    val exposedRedWorkdays: Int = 5,
    val maintenanceYellowRatio: Double = 0.75,
    val trendWindowDays: Long = 30,
    val trendStableRatio: Double = 0.05,
    val historyMonths: Long = 6,
    val levelNewWorkdays: Int = 5,
    val levelChronicMonths: Long = 3,
)
