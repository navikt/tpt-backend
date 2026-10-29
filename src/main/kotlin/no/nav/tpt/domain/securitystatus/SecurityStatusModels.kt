package no.nav.tpt.domain.securitystatus

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class SecurityStatusColor {
    @SerialName("green") GREEN,
    @SerialName("yellow") YELLOW,
    @SerialName("red") RED,
}

@Serializable
enum class SecurityLevel {
    @SerialName("new") NEW,
    @SerialName("ongoing") ONGOING,
    @SerialName("chronic") CHRONIC,
}

@Serializable
enum class TrendDirection {
    @SerialName("worse") WORSE,
    @SerialName("stable") STABLE,
    @SerialName("improving") IMPROVING,
}

@Serializable
data class AppPastDeadline(
    val app: String,
    val workdaysOver: Int,
)

@Serializable
data class AppOverdueRebuild(
    val app: String,
    val daysOver: Int,
)

@Serializable
data class ExposedStatus(
    val status: SecurityStatusColor,
    val since: String?,
    val appsPastDeadline: List<AppPastDeadline>,
)

@Serializable
data class TrendStatus(
    val status: SecurityStatusColor,
    val since: String?,
    val direction: TrendDirection,
    val appsWithOverduePerMonth: List<Int>,
)

@Serializable
data class MaintenanceStatus(
    val status: SecurityStatusColor,
    val since: String?,
    val upToDate: Int,
    val total: Int,
    val overdueRebuild: List<AppOverdueRebuild>,
)

@Serializable
data class MonthlySecurityHistory(
    val month: String,
    val throughDate: String,
    val onTrackDays: Int,
    val needsAttentionDays: Int,
    val actNowDays: Int,
    val missingDays: Int,
    val provisional: Boolean,
)

@Serializable
data class SecurityStatusMeasurement(
    val deployMaxAgeDays: Long,
    val exposedRedWorkdays: Int,
    val maintenanceYellowRatio: Double,
    val trendWindowDays: Long,
    val trendStableRatio: Double,
    val historyMonths: Long,
    val levelNewWorkdays: Int,
    val levelChronicMonths: Long,
    val criticalWorkdays: Int,
    val nonCriticalMonths: Long,
    val timeZone: String,
)

@Serializable
data class TeamSecurityStatus(
    val team: String,
    val applicationCount: Int,
    val level: SecurityLevel?,
    val history: List<MonthlySecurityHistory>,
    val historyAvailableFrom: String,
    val exposed: ExposedStatus,
    val trend: TrendStatus,
    val maintenance: MaintenanceStatus,
)

@Serializable
data class SecurityStatusResponse(
    val teams: List<TeamSecurityStatus>,
    val generatedAt: String,
    val measurement: SecurityStatusMeasurement,
)
