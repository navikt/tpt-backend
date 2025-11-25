package no.nav.tpt.infrastructure.vulns

import no.nav.tpt.domain.VulnResponse
import no.nav.tpt.domain.VulnTeamDto
import no.nav.tpt.domain.VulnVulnerabilityDto
import no.nav.tpt.domain.VulnWorkloadDto
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.nais.ImageTagParser
import no.nav.tpt.infrastructure.nais.NaisApiService

class VulnServiceImpl(
    private val naisApiService: NaisApiService,
    private val kevService: KevService,
    private val epssService: EpssService,
) : VulnService {

    override suspend fun fetchVulnerabilitiesForUser(email: String): VulnResponse {
        val applicationsData = naisApiService.getApplicationsForUser(email)
        val vulnerabilitiesData = naisApiService.getVulnerabilitiesForUser(email)
        val kevCatalog = kevService.getKevCatalog()

        val kevCveIds = kevCatalog.vulnerabilities.map { it.cveID }.toSet()

        val allCveIds = vulnerabilitiesData.teams
            .flatMap { it.workloads }
            .flatMap { it.vulnerabilities }
            .map { it.identifier }
            .distinct()

        val epssScores = epssService.getEpssScores(allCveIds)

        val teams = vulnerabilitiesData.teams.mapNotNull { teamVulns ->
            val teamSlug = teamVulns.teamSlug

            val teamApplications = applicationsData.teams
                .firstOrNull { it.teamSlug == teamSlug }
                ?.applications ?: emptyList()

            val appIngressMap = teamApplications.associate { app ->
                app.name to app.ingressTypes
            }

            val workloads = teamVulns.workloads.mapNotNull { workload ->
                val vulnerabilities = workload.vulnerabilities.map { vuln ->
                    val epssScore = epssScores[vuln.identifier]
                    VulnVulnerabilityDto(
                        identifier = vuln.identifier,
                        severity = vuln.severity,
                        suppressed = vuln.suppressed,
                        hasKevEntry = kevCveIds.contains(vuln.identifier),
                        epssScore = epssScore?.epss,
                        epssPercentile = epssScore?.percentile
                    )
                }

                if (vulnerabilities.isNotEmpty()) {
                    val buildTime = workload.imageTag?.let { tag ->
                        ImageTagParser.extractBuildDate(tag)?.toString()
                    }
                    VulnWorkloadDto(
                        id = workload.id,
                        name = workload.name,
                        ingressTypes = appIngressMap[workload.name]?.map { it.name } ?: emptyList(),
                        buildTime = buildTime,
                        vulnerabilities = vulnerabilities
                    )
                } else {
                    null
                }
            }

            if (workloads.isNotEmpty()) {
                VulnTeamDto(
                    team = teamSlug,
                    workloads = workloads
                )
            } else {
                null
            }
        }

        return VulnResponse(teams = teams)
    }
}

