package no.nav.tpt.infrastructure.admin

import kotlinx.serialization.json.Json
import no.nav.tpt.domain.admin.AdminService
import no.nav.tpt.domain.admin.TeamsOverviewResponse
import no.nav.tpt.domain.admin.TeamsSlaReportResponse
import no.nav.tpt.plugins.ServiceUnavailableException
import org.slf4j.LoggerFactory

class AdminServiceImpl(
    private val adminReportRepository: AdminReportRepository,
) : AdminService {
    private val logger = LoggerFactory.getLogger(AdminServiceImpl::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun getTeamsOverview(): TeamsOverviewResponse {
        val row = adminReportRepository.getReport(REPORT_OVERVIEW)
            ?: throw ServiceUnavailableException(
                "Teams overview report has not been generated yet. Trigger a sync or report refresh first."
            )
        logger.debug("Serving pre-computed teams overview (generated at ${row.generatedAt})")
        return json.decodeFromString(row.payload)
    }

    override suspend fun getTeamsSlaReport(): TeamsSlaReportResponse {
        val row = adminReportRepository.getReport(REPORT_SLA)
            ?: throw ServiceUnavailableException(
                "Teams SLA report has not been generated yet. Trigger a sync or report refresh first."
            )
        logger.debug("Serving pre-computed teams SLA report (generated at ${row.generatedAt})")
        return json.decodeFromString(row.payload)
    }

    companion object {
        const val REPORT_OVERVIEW = "teams_overview"
        const val REPORT_SLA      = "teams_sla"
    }
}
