package no.nav.appsecguide.infrastructure.vulns

import no.nav.appsecguide.domain.VulnResponse
import no.nav.appsecguide.domain.VulnTeamDto
import no.nav.appsecguide.domain.VulnVulnerabilityDto
import no.nav.appsecguide.domain.VulnWorkloadDto
import no.nav.appsecguide.infrastructure.cisa.KevService
import no.nav.appsecguide.infrastructure.nais.NaisApiService

class VulnServiceImpl(
    private val naisApiService: NaisApiService,
    private val kevService: KevService,
) : VulnService {

    override suspend fun fetchVulnerabilitiesForUser(email: String): VulnResponse {
        val applicationsData = naisApiService.getApplicationsForUser(email)
        val vulnerabilitiesData = naisApiService.getVulnerabilitiesForUser(email)
        val kevCatalog = kevService.getKevCatalog()

        val kevCveIds = kevCatalog.vulnerabilities.map { it.cveID }.toSet()

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
                    VulnVulnerabilityDto(
                        identifier = vuln.identifier,
                        severity = vuln.severity,
                        suppressed = vuln.suppressed,
                        hasKevEntry = kevCveIds.contains(vuln.identifier)
                    )
                }

                if (vulnerabilities.isNotEmpty()) {
                    VulnWorkloadDto(
                        name = workload.name,
                        ingressTypes = appIngressMap[workload.name] ?: emptyList(),
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

