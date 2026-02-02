package no.nav.tpt.infrastructure.admin

import no.nav.tpt.domain.admin.*
import no.nav.tpt.domain.vulnerability.VulnerabilityRepository
import no.nav.tpt.infrastructure.vulnerability.VulnerabilitySearchService
import org.slf4j.LoggerFactory
import java.time.Duration
import java.time.Instant

class AdminServiceImpl(
    private val vulnerabilityRepository: VulnerabilityRepository,
    private val vulnerabilitySearchService: VulnerabilitySearchService
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
        
        val allVulnerabilities = vulnerabilityRepository.getAllActiveVulnerabilities()
        logger.debug("Found ${allVulnerabilities.size} active vulnerabilities in database")
        
        val allTeamSlugs = allVulnerabilities.map { it.teamSlug }.distinct()
        
        val slaReport = vulnerabilitySearchService.getOverdueSlaReport(allTeamSlugs)
        
        val teamSlaOverviews = slaReport.teams.map { teamStatus ->
            TeamSlaOverview(
                teamSlug = teamStatus.teamSlug,
                totalVulnerabilities = teamStatus.totalVulnerabilities,
                criticalOverdue = teamStatus.criticalOverdue,
                nonCriticalOverdue = teamStatus.nonCriticalOverdue,
                criticalWithinSla = teamStatus.criticalWithinSla,
                nonCriticalWithinSla = teamStatus.nonCriticalWithinSla,
                repositoriesOutOfSla = teamStatus.repositoriesOutOfSla,
                maxDaysOverdue = teamStatus.maxDaysOverdue
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
            generatedAt = slaReport.generatedAt
        )
    }
}
