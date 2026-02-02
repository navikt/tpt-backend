package no.nav.tpt.domain.admin

import kotlinx.serialization.Serializable

interface AdminService {
    suspend fun getTeamsOverview(): TeamsOverviewResponse
    suspend fun getTeamsSlaReport(): TeamsSlaReportResponse
}

@Serializable
data class TeamsOverviewResponse(
    val teams: List<TeamOverview>,
    val totalTeams: Int,
    val totalVulnerabilities: Int,
    val generatedAt: String
)

@Serializable
data class TeamOverview(
    val teamSlug: String,
    val totalVulnerabilities: Int,
    val criticalVulnerabilities: Int,
    val highVulnerabilities: Int,
    val mediumVulnerabilities: Int,
    val lowVulnerabilities: Int,
    val unknownVulnerabilities: Int
)

@Serializable
data class TeamsSlaReportResponse(
    val teams: List<TeamSlaOverview>,
    val totalTeams: Int,
    val totalOverdue: Int,
    val totalCriticalOverdue: Int,
    val totalNonCriticalOverdue: Int,
    val generatedAt: String
)

@Serializable
data class TeamSlaOverview(
    val teamSlug: String,
    val totalVulnerabilities: Int,
    val criticalOverdue: Int,
    val nonCriticalOverdue: Int,
    val criticalWithinSla: Int,
    val nonCriticalWithinSla: Int
)
