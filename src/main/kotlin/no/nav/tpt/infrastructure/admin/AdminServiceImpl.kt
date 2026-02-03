package no.nav.tpt.infrastructure.admin

import no.nav.tpt.domain.admin.*
import no.nav.tpt.domain.vulnerability.VulnerabilityRepository
import org.slf4j.LoggerFactory
import java.time.Duration
import java.time.Instant

class AdminServiceImpl(
    private val vulnerabilityRepository: VulnerabilityRepository
) : AdminService {
    private val logger = LoggerFactory.getLogger(AdminServiceImpl::class.java)
    
    private val overviewCache = AdminReportCache<TeamsOverviewResponse>(ttl = Duration.ofMinutes(30))
    private val slaCache = AdminReportCache<TeamsSlaReportResponse>(ttl = Duration.ofMinutes(30))
    
    override suspend fun getTeamsOverview(): TeamsOverviewResponse = overviewCache.get {
        logger.debug("Generating teams overview report (not cached)")
        
        val teamCounts = vulnerabilityRepository.getTeamVulnerabilityCounts()
        logger.debug("Aggregated ${teamCounts.size} teams from database")
        
        val teamOverviews = teamCounts.map { count ->
            TeamOverview(
                teamSlug = count.teamSlug,
                totalVulnerabilities = count.totalCount,
                criticalVulnerabilities = count.criticalCount,
                highVulnerabilities = count.highCount,
                mediumVulnerabilities = count.mediumCount,
                lowVulnerabilities = count.lowCount,
                unknownVulnerabilities = count.unknownCount
            )
        }
        
        TeamsOverviewResponse(
            teams = teamOverviews,
            totalTeams = teamOverviews.size,
            totalVulnerabilities = teamCounts.sumOf { it.totalCount },
            generatedAt = Instant.now().toString()
        )
    }
    
    override suspend fun getTeamsSlaReport(): TeamsSlaReportResponse = slaCache.get {
        logger.debug("Generating teams SLA report (not cached)")
        
        val teamSlaSummaries = vulnerabilityRepository.getTeamSlaSummaries()
        logger.debug("Calculated SLA for ${teamSlaSummaries.size} teams in database")
        
        val teamSlaOverviews = teamSlaSummaries.map { summary ->
            TeamSlaOverview(
                teamSlug = summary.teamSlug,
                totalVulnerabilities = summary.totalVulnerabilities,
                criticalOverdue = summary.criticalOverdue,
                nonCriticalOverdue = summary.nonCriticalOverdue,
                criticalWithinSla = summary.criticalWithinSla,
                nonCriticalWithinSla = summary.nonCriticalWithinSla,
                repositoriesOutOfSla = summary.repositoriesOutOfSla,
                maxDaysOverdue = summary.maxDaysOverdue
            )
        }
        
        val totalCriticalOverdue = teamSlaOverviews.sumOf { it.criticalOverdue }
        val totalNonCriticalOverdue = teamSlaOverviews.sumOf { it.nonCriticalOverdue }
        
        TeamsSlaReportResponse(
            teams = teamSlaOverviews,
            totalTeams = teamSlaOverviews.size,
            totalOverdue = totalCriticalOverdue + totalNonCriticalOverdue,
            totalCriticalOverdue = totalCriticalOverdue,
            totalNonCriticalOverdue = totalNonCriticalOverdue,
            generatedAt = Instant.now().toString()
        )
    }
}
