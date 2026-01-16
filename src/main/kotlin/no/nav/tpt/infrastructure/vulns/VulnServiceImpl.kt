package no.nav.tpt.infrastructure.vulns

import no.nav.tpt.domain.VulnResponse
import no.nav.tpt.domain.VulnTeamDto
import no.nav.tpt.domain.VulnVulnerabilityDto
import no.nav.tpt.domain.VulnWorkloadDto
import no.nav.tpt.domain.risk.RiskScorer
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.nais.ImageTagParser
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.nvd.NvdRepository
import no.nav.tpt.infrastructure.purl.PurlParser
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService

class VulnServiceImpl(
    private val naisApiService: NaisApiService,
    private val kevService: KevService,
    private val epssService: EpssService,
    private val nvdRepository: NvdRepository,
    private val riskScorer: RiskScorer,
    private val teamkatalogenService: TeamkatalogenService
) : VulnService {

    override suspend fun fetchVulnerabilitiesForUser(email: String, bypassCache: Boolean): VulnResponse {
        var vulnerabilitiesData = naisApiService.getVulnerabilitiesForUser(email, bypassCache)

        // if a user does not have any teams with vulnerabilities in nais, this indicates that they might belong to a nais team
        // so we check teamkatalogen for team membership and fetch vulnerabilities for those teams
        if(vulnerabilitiesData.teams.isEmpty()) {
            val membershipResponse = teamkatalogenService.getMembershipByEmail(email)
            val teamVulnsList = mutableListOf<no.nav.tpt.infrastructure.nais.TeamVulnerabilitiesData>()
            for(naisTeam in membershipResponse.naisTeams) {
                val teamVulns = naisApiService.getVulnerabilitiesForTeam(naisTeam, bypassCache)
                teamVulnsList.addAll(teamVulns.teams)
            }
            vulnerabilitiesData = no.nav.tpt.infrastructure.nais.UserVulnerabilitiesData(
                teams = teamVulnsList
            )
        }

        val kevCatalog = kevService.getKevCatalog()

        val kevCveIds = kevCatalog.vulnerabilities.map { it.cveID }.toSet()

        val allCveIds = vulnerabilitiesData.teams
            .flatMap { it.workloads }
            .flatMap { it.vulnerabilities }
            .map { it.identifier }
            .distinct()

        val epssScores = epssService.getEpssScores(allCveIds)
        val nvdData = nvdRepository.getCveDataBatch(allCveIds)

        val teams = vulnerabilitiesData.teams.mapNotNull { teamVulns ->
            val teamSlug = teamVulns.teamSlug

            val workloads = teamVulns.workloads.mapNotNull { workload ->
                val ingressTypes = workload.ingressTypes
                val buildDate = workload.imageTag?.let { tag ->
                    ImageTagParser.extractBuildDate(tag)
                }

                val vulnerabilities = workload.vulnerabilities.map { vuln ->
                    val epssScore = epssScores[vuln.identifier]
                    val hasKevEntry = kevCveIds.contains(vuln.identifier)
                    val cveData = nvdData[vuln.identifier]

                    val riskContext = no.nav.tpt.domain.risk.VulnerabilityRiskContext(
                        severity = vuln.severity,
                        ingressTypes = ingressTypes,
                        hasKevEntry = hasKevEntry,
                        epssScore = epssScore?.epss,
                        suppressed = vuln.suppressed,
                        environment = workload.environment,
                        buildDate = buildDate,
                        hasExploitReference = cveData?.hasExploitReference ?: false,
                        hasPatchReference = cveData?.hasPatchReference ?: false,
                        cveDaysOld = cveData?.daysOld
                    )
                    val riskResult = riskScorer.calculateRiskScore(riskContext)

                    VulnVulnerabilityDto(
                        identifier = vuln.identifier,
                        name = PurlParser.extractPackageName(vuln.packageName),
                        packageName = vuln.packageName,
                        description = vuln.description,
                        vulnerabilityDetailsLink = vuln.vulnerabilityDetailsLink,
                        riskScore = riskResult.score,
                        riskScoreBreakdown = riskResult.breakdown
                    )
                }

                if (vulnerabilities.isNotEmpty()) {
                    VulnWorkloadDto(
                        id = workload.id,
                        name = workload.name,
                        workloadType = workload.workloadType,
                        environment = workload.environment,
                        repository = workload.repository,
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
