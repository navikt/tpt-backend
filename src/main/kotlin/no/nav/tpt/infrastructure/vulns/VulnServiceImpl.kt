package no.nav.tpt.infrastructure.vulns

import no.nav.tpt.domain.VulnResponse
import no.nav.tpt.domain.VulnTeamDto
import no.nav.tpt.domain.VulnVulnerabilityDto
import no.nav.tpt.domain.VulnWorkloadDto
import no.nav.tpt.domain.risk.RiskScorer
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.vulnerability.VulnerabilityDataService
import no.nav.tpt.infrastructure.cisa.KevCatalog
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.nais.ImageTagParser
import no.nav.tpt.infrastructure.nvd.NvdRepository
import no.nav.tpt.infrastructure.purl.PurlParser
import org.slf4j.LoggerFactory

class VulnServiceImpl(
    private val vulnerabilityDataService: VulnerabilityDataService,
    private val kevService: KevService,
    private val epssService: EpssService,
    private val nvdRepository: NvdRepository,
    private val riskScorer: RiskScorer,
    private val userContextService: UserContextService,
    private val gitHubRepository: GitHubRepository
) : VulnService {
    private val logger = LoggerFactory.getLogger(VulnServiceImpl::class.java)

    private data class CveEnrichmentData(
        val kevCveIds: Set<String>,
        val epssScores: Map<String, no.nav.tpt.infrastructure.epss.EpssScore>,
        val nvdData: Map<String, no.nav.tpt.infrastructure.nvd.NvdCveData>
    )

    private suspend fun fetchCveEnrichmentData(cveIds: List<String>): CveEnrichmentData {
        val kevCatalog = try {
            kevService.getKevCatalog()
        } catch (e: Exception) {
            // KevServiceImpl should handle this, but defensive catch in case
            logger.warn("Unexpected error fetching KEV catalog, using empty KEV data: ${e.message}")
            KevCatalog(
                title = "CISA Catalog of Known Exploited Vulnerabilities",
                catalogVersion = "unavailable",
                dateReleased = "unavailable",
                count = 0,
                vulnerabilities = emptyList()
            )
        }
        val kevCveIds = kevCatalog.vulnerabilities.map { it.cveID }.toSet()
        val epssScores = epssService.getEpssScores(cveIds)
        val nvdData = nvdRepository.getCveDataBatch(cveIds)

        return CveEnrichmentData(kevCveIds, epssScores, nvdData)
    }

    override suspend fun fetchVulnerabilitiesForUser(email: String): VulnResponse {
        val userContext = userContextService.getUserContext(email)

        if (userContext.teams.isEmpty()) {
            return VulnResponse(userRole = userContext.role, teams = emptyList())
        }

        val vulnerabilitiesData = vulnerabilityDataService.getVulnerabilitiesForUser(email)

        val allCveIds = vulnerabilitiesData.teams
            .flatMap { it.workloads }
            .flatMap { it.vulnerabilities }
            .map { it.identifier }
            .distinct()

        val enrichmentData = fetchCveEnrichmentData(allCveIds)

        val teams = vulnerabilitiesData.teams.mapNotNull { teamVulns ->
            val teamSlug = teamVulns.teamSlug

            val workloads = teamVulns.workloads.mapNotNull { workload ->
                val ingressTypes = workload.ingressTypes
                val buildDate = workload.imageTag?.let { tag ->
                    ImageTagParser.extractBuildDate(tag)
                }

                val vulnerabilities = workload.vulnerabilities.map { vuln ->
                    val epssScore = enrichmentData.epssScores[vuln.identifier]
                    val hasKevEntry = enrichmentData.kevCveIds.contains(vuln.identifier)
                    val cveData = enrichmentData.nvdData[vuln.identifier]

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

        return VulnResponse(userRole = userContext.role, teams = teams)
    }

    override suspend fun fetchGitHubVulnerabilitiesForUser(email: String): no.nav.tpt.domain.GitHubVulnResponse {
        val userContext = userContextService.getUserContext(email)

        if (userContext.teams.isEmpty()) {
            return no.nav.tpt.domain.GitHubVulnResponse(userRole = userContext.role, teams = emptyList())
        }

        val gitHubRepositoriesData = gitHubRepository.getRepositoriesByTeams(userContext.teams)

        val allCveIds = gitHubRepositoriesData
            .flatMap { repo -> gitHubRepository.getVulnerabilities(repo.nameWithOwner) }
            .flatMap { it.identifiers }
            .filter { it.type.equals("CVE", ignoreCase = true) }
            .map { it.value }
            .distinct()

        val enrichmentData = fetchCveEnrichmentData(allCveIds)

        val teamRepositories = mutableMapOf<String, MutableList<no.nav.tpt.domain.GitHubVulnRepositoryDto>>()

        gitHubRepositoriesData.forEach { repo ->
            val repoVulns = gitHubRepository.getVulnerabilities(repo.nameWithOwner)

            val vulnerabilities = repoVulns.mapNotNull { vuln ->
                val cveIdentifier = vuln.identifiers
                    .firstOrNull { it.type.equals("CVE", ignoreCase = true) }
                    ?.value

                if (cveIdentifier == null) return@mapNotNull null

                val epssScore = enrichmentData.epssScores[cveIdentifier]
                val hasKevEntry = enrichmentData.kevCveIds.contains(cveIdentifier)
                val cveData = enrichmentData.nvdData[cveIdentifier]

                val riskContext = no.nav.tpt.domain.risk.VulnerabilityRiskContext(
                    severity = vuln.severity,
                    ingressTypes = emptyList(),
                    hasKevEntry = hasKevEntry,
                    epssScore = epssScore?.epss,
                    suppressed = false,
                    environment = null,
                    buildDate = null,
                    hasExploitReference = cveData?.hasExploitReference ?: false,
                    hasPatchReference = cveData?.hasPatchReference ?: false,
                    cveDaysOld = cveData?.daysOld
                )
                val riskResult = riskScorer.calculateRiskScore(riskContext)

                no.nav.tpt.domain.GitHubVulnVulnerabilityDto(
                    identifier = cveIdentifier,
                    packageName = vuln.packageName,
                    packageEcosystem = vuln.packageEcosystem,
                    description = vuln.summary ?: cveData?.description,
                    summary = vuln.summary,
                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/$cveIdentifier",
                    riskScore = riskResult.score,
                    riskScoreBreakdown = riskResult.breakdown,
                    dependencyScope = vuln.dependencyScope,
                    dependabotUpdatePullRequestUrl = vuln.dependabotUpdatePullRequestUrl,
                    publishedAt = vuln.publishedAt?.toString(),
                    cvssScore = vuln.cvssScore
                )
            }

            if (vulnerabilities.isNotEmpty()) {
                val repoDto = no.nav.tpt.domain.GitHubVulnRepositoryDto(
                    nameWithOwner = repo.nameWithOwner,
                    vulnerabilities = vulnerabilities
                )

                repo.naisTeams.forEach { teamSlug ->
                    teamRepositories.getOrPut(teamSlug) { mutableListOf() }.add(repoDto)
                }
            }
        }

        val teams = teamRepositories.map { (teamSlug, repositories) ->
            no.nav.tpt.domain.GitHubVulnTeamDto(
                team = teamSlug,
                repositories = repositories
            )
        }

        return no.nav.tpt.domain.GitHubVulnResponse(userRole = userContext.role, teams = teams)
    }
}
