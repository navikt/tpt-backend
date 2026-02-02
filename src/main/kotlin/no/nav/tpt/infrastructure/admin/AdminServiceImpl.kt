package no.nav.tpt.infrastructure.admin

import no.nav.tpt.domain.admin.*
import no.nav.tpt.domain.vulnerability.VulnerabilityRepository
import no.nav.tpt.infrastructure.vulnerability.VulnerabilitySearchService
import org.slf4j.LoggerFactory
import java.time.Instant

class AdminServiceImpl(
    private val vulnerabilityRepository: VulnerabilityRepository,
    private val vulnerabilitySearchService: VulnerabilitySearchService
) : AdminService {
    private val logger = LoggerFactory.getLogger(AdminServiceImpl::class.java)
    
    override suspend fun getTeamsOverview(): TeamsOverviewResponse {
        logger.debug("Fetching teams overview from database")
        
        val allVulnerabilities = vulnerabilityRepository.getAllActiveVulnerabilities()
        logger.debug("Found ${allVulnerabilities.size} active vulnerabilities in database")
        
        val teamGroups = allVulnerabilities.groupBy { it.teamSlug }
        
        val teamOverviews = teamGroups.map { (teamSlug, vulns) ->
            val severityCounts = vulns.groupBy { it.severity?.uppercase() ?: "UNKNOWN" }
                .mapValues { it.value.size }
            
            TeamOverview(
                teamSlug = teamSlug,
                totalVulnerabilities = vulns.size,
                criticalVulnerabilities = severityCounts["CRITICAL"] ?: 0,
                highVulnerabilities = severityCounts["HIGH"] ?: 0,
                mediumVulnerabilities = severityCounts["MEDIUM"] ?: 0,
                lowVulnerabilities = severityCounts["LOW"] ?: 0,
                unknownVulnerabilities = severityCounts["UNKNOWN"] ?: 0
            )
        }.sortedByDescending { it.totalVulnerabilities }
        
        return TeamsOverviewResponse(
            teams = teamOverviews,
            totalTeams = teamOverviews.size,
            totalVulnerabilities = allVulnerabilities.size,
            generatedAt = Instant.now().toString()
        )
    }
    
    override suspend fun getTeamsSlaReport(): TeamsSlaReportResponse {
        logger.debug("Fetching teams SLA report from database")
        
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
                nonCriticalWithinSla = teamStatus.nonCriticalWithinSla
            )
        }
        
        val totalCriticalOverdue = teamSlaOverviews.sumOf { it.criticalOverdue }
        val totalNonCriticalOverdue = teamSlaOverviews.sumOf { it.nonCriticalOverdue }
        
        return TeamsSlaReportResponse(
            teams = teamSlaOverviews,
            totalTeams = teamSlaOverviews.size,
            totalOverdue = totalCriticalOverdue + totalNonCriticalOverdue,
            totalCriticalOverdue = totalCriticalOverdue,
            totalNonCriticalOverdue = totalNonCriticalOverdue,
            generatedAt = slaReport.generatedAt
        )
    }
}
