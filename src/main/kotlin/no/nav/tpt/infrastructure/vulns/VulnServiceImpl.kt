package no.nav.tpt.infrastructure.vulns

import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import no.nav.tpt.domain.DependencyCategory
import no.nav.tpt.domain.VulnResponse
import no.nav.tpt.domain.VulnTeamDto
import no.nav.tpt.domain.VulnVulnerabilityDto
import no.nav.tpt.domain.VulnWorkloadDto
import no.nav.tpt.domain.risk.RiskScorer
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.user.UserRole
import no.nav.tpt.domain.vulnerability.VulnerabilityDataService
import no.nav.tpt.infrastructure.cisa.KevCatalog
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.gcve.GcveCveData
import no.nav.tpt.infrastructure.gcve.GcveRepository
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.nais.ImageTagParser
import no.nav.tpt.infrastructure.nvd.NvdRepository
import no.nav.tpt.infrastructure.vulnrichment.VulnrichmentRepository
import no.nav.tpt.infrastructure.vulnrichment.VulnrichmentSyncService
import no.nav.tpt.infrastructure.vulns.utils.PurlParser
import org.slf4j.LoggerFactory

class VulnServiceImpl(
    private val vulnerabilityDataService: VulnerabilityDataService,
    private val kevService: KevService,
    private val epssService: EpssService,
    private val nvdRepository: NvdRepository,
    private val vulnrichmentRepository: VulnrichmentRepository,
    private val vulnrichmentSyncService: VulnrichmentSyncService,
    private val riskScorer: RiskScorer,
    private val userContextService: UserContextService,
    private val gitHubRepository: GitHubRepository,
    private val gcveMissPathService: no.nav.tpt.infrastructure.gcve.GcveMissPathService? = null,
    private val gcveRepository: GcveRepository? = null,
    private val useGcveDataSource: Boolean = false,
) : VulnService {
    private val logger = LoggerFactory.getLogger(VulnServiceImpl::class.java)

    private data class CveEnrichmentData(
        val kevCveIds: Set<String>,
        val kevRansomwareCveIds: Set<String>,
        val epssScores: Map<String, no.nav.tpt.infrastructure.epss.EpssScore>,
        val nvdData: Map<String, no.nav.tpt.infrastructure.nvd.NvdCveData>,
        val vulnrichmentData: Map<String, no.nav.tpt.infrastructure.vulnrichment.VulnrichmentData>,
        val gcveData: Map<String, GcveCveData>,
    )

    private fun triggerGcveMissPathFetchAsync(cveIds: List<String>) {
        if (gcveMissPathService == null) {
            logger.debug("GCVE miss-path service not available, skipping async fetch")
            return
        }

        if (cveIds.isEmpty()) {
            return
        }

        // Fire and forget: don't block on this
        GlobalScope.launch {
            try {
                logger.debug("Async GCVE miss-path fetch triggered for ${cveIds.size} CVEs")
                val fetched = gcveMissPathService.fetchMissing(cveIds)
                logger.info("Async GCVE miss-path fetch completed: $fetched/${cveIds.size} CVEs fetched")
            } catch (e: Exception) {
                logger.warn("Async GCVE miss-path fetch failed: ${e.message}", e)
            }
        }
    }

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
        val kevRansomwareCveIds = kevCatalog.vulnerabilities
            .filter { it.knownRansomwareCampaignUse.equals("Known", ignoreCase = true) }
            .map { it.cveID }
            .toSet()
        val epssScores = epssService.getEpssScores(cveIds)
        val nvdData = nvdRepository.getCveDataBatch(cveIds)
        try {
            vulnrichmentSyncService.ensureCached(cveIds)
        } catch (e: Exception) {
            logger.warn("Failed to ensure Vulnrichment cache, continuing without it: ${e.message}")
        }
        val vulnrichmentData = try {
            vulnrichmentRepository.getVulnrichmentDataBatch(cveIds)
        } catch (e: Exception) {
            logger.warn("Failed to fetch Vulnrichment data, continuing without it: ${e.message}")
            emptyMap()
        }
        val gcveData = try {
            gcveRepository?.getCveDataBatch(cveIds) ?: emptyMap()
        } catch (e: Exception) {
            logger.warn("Failed to fetch GCVE data, continuing without it: ${e.message}")
            emptyMap()
        }

        return CveEnrichmentData(kevCveIds, kevRansomwareCveIds, epssScores, nvdData, vulnrichmentData, gcveData)
    }

    private fun buildRiskContext(
        cveId: String,
        severity: String,
        ingressTypes: List<String>,
        suppressed: Boolean,
        environment: String?,
        buildDate: java.time.LocalDate?,
        enrichmentData: CveEnrichmentData,
    ): no.nav.tpt.domain.risk.VulnerabilityRiskContext {
        val epssScore = enrichmentData.epssScores[cveId]
        val hasKevEntry = enrichmentData.kevCveIds.contains(cveId)
        val hasRansomwareCampaignUse = enrichmentData.kevRansomwareCveIds.contains(cveId)

        return if (useGcveDataSource) {
            val gcve = enrichmentData.gcveData[cveId]
            no.nav.tpt.domain.risk.VulnerabilityRiskContext(
                severity = severity,
                ingressTypes = ingressTypes,
                hasKevEntry = gcve?.hasKevEntry ?: hasKevEntry,
                epssScore = epssScore?.epss,
                suppressed = suppressed,
                environment = environment,
                buildDate = buildDate,
                hasExploitReference = gcve?.hasExploitReference ?: false,
                hasPatchReference = gcve?.hasPatchReference ?: false,
                cveDaysOld = gcve?.daysOld,
                hasRansomwareCampaignUse = hasRansomwareCampaignUse,
                ssvcExploitation = gcve?.ssvcExploitation,
                ssvcAutomatable = gcve?.ssvcAutomatable,
                ssvcTechnicalImpact = gcve?.ssvcTechnicalImpact,
                nvdVulnStatus = null,
            )
        } else {
            val cveData = enrichmentData.nvdData[cveId]
            val vulnrichmentEntry = enrichmentData.vulnrichmentData[cveId]
            no.nav.tpt.domain.risk.VulnerabilityRiskContext(
                severity = severity,
                ingressTypes = ingressTypes,
                hasKevEntry = hasKevEntry,
                epssScore = epssScore?.epss,
                suppressed = suppressed,
                environment = environment,
                buildDate = buildDate,
                hasExploitReference = cveData?.hasExploitReference ?: false,
                hasPatchReference = cveData?.hasPatchReference ?: false,
                cveDaysOld = cveData?.daysOld,
                hasRansomwareCampaignUse = hasRansomwareCampaignUse,
                ssvcExploitation = vulnrichmentEntry?.exploitationStatus,
                ssvcAutomatable = vulnrichmentEntry?.automatable,
                ssvcTechnicalImpact = vulnrichmentEntry?.technicalImpact,
                nvdVulnStatus = cveData?.vulnStatus,
            )
        }
    }

    override suspend fun fetchVulnerabilitiesForUser(email: String, groups: List<String>): VulnResponse {
        val userContext = userContextService.getUserContext(email, groups)

        if (userContext.teams.isEmpty()) {
            return VulnResponse(userRole = userContext.role, teams = emptyList())
        }

        val vulnerabilitiesData = vulnerabilityDataService.getVulnerabilitiesForTeams(userContext.teams)

        val allCveIds = vulnerabilitiesData.teams
            .flatMap { it.workloads }
            .flatMap { it.vulnerabilities }
            .map { it.identifier }
            .filter { it.startsWith("CVE-", ignoreCase = true) }
            .distinct()

        triggerGcveMissPathFetchAsync(allCveIds)
        val enrichmentData = fetchCveEnrichmentData(allCveIds)

        val teams = vulnerabilitiesData.teams.mapNotNull { teamVulns ->
            val teamSlug = teamVulns.teamSlug

            val workloads = teamVulns.workloads.mapNotNull { workload ->
                val ingressTypes = workload.ingressTypes
                val buildDate = workload.imageTag?.let { tag ->
                    ImageTagParser.extractBuildDate(tag)
                }

                val vulnerabilities = workload.vulnerabilities.map { vuln ->
                    val riskContext = buildRiskContext(
                        cveId = vuln.identifier,
                        severity = vuln.severity,
                        ingressTypes = ingressTypes,
                        suppressed = vuln.suppressed,
                        environment = workload.environment,
                        buildDate = buildDate,
                        enrichmentData = enrichmentData,
                    )
                    val riskResult = riskScorer.calculateRiskScore(riskContext)

                    VulnVulnerabilityDto(
                        identifier = vuln.identifier,
                        name = PurlParser.extractPackageName(vuln.packageName),
                        packageName = vuln.packageName,
                        packageEcosystem = vuln.packageType,
                        description = vuln.description,
                        vulnerabilityDetailsLink = vuln.vulnerabilityDetailsLink,
                        riskScore = riskResult.score,
                        riskScoreBreakdown = riskResult.breakdown,
                        dependencyCategory = DependencyCategory.fromPurlType(vuln.packageType).name
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

    override suspend fun fetchVulnerabilitiesForTeam(teamSlug: String): VulnResponse {
        val vulnerabilitiesData = vulnerabilityDataService.getVulnerabilitiesForTeam(teamSlug)

        val allCveIds = vulnerabilitiesData.teams
            .flatMap { it.workloads }
            .flatMap { it.vulnerabilities }
            .map { it.identifier }
            .filter { it.startsWith("CVE-", ignoreCase = true) }
            .distinct()

        triggerGcveMissPathFetchAsync(allCveIds)
        val enrichmentData = fetchCveEnrichmentData(allCveIds)

        val teams = vulnerabilitiesData.teams.mapNotNull { teamVulns ->
            val workloads = teamVulns.workloads.mapNotNull { workload ->
                val ingressTypes = workload.ingressTypes
                val buildDate = workload.imageTag?.let { tag ->
                    ImageTagParser.extractBuildDate(tag)
                }

                val vulnerabilities = workload.vulnerabilities.map { vuln ->
                    val riskContext = buildRiskContext(
                        cveId = vuln.identifier,
                        severity = vuln.severity,
                        ingressTypes = ingressTypes,
                        suppressed = vuln.suppressed,
                        environment = workload.environment,
                        buildDate = buildDate,
                        enrichmentData = enrichmentData,
                    )
                    val riskResult = riskScorer.calculateRiskScore(riskContext)

                    VulnVulnerabilityDto(
                        identifier = vuln.identifier,
                        name = PurlParser.extractPackageName(vuln.packageName),
                        packageName = vuln.packageName,
                        packageEcosystem = vuln.packageType,
                        description = vuln.description,
                        vulnerabilityDetailsLink = vuln.vulnerabilityDetailsLink,
                        riskScore = riskResult.score,
                        riskScoreBreakdown = riskResult.breakdown,
                        dependencyCategory = DependencyCategory.fromPurlType(vuln.packageType).name
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
                    team = teamVulns.teamSlug,
                    workloads = workloads
                )
            } else {
                null
            }
        }

        return VulnResponse(userRole = UserRole.ADMIN, teams = teams)
    }

    override suspend fun fetchGitHubVulnerabilitiesForUser(email: String, groups: List<String>): no.nav.tpt.domain.GitHubVulnResponse {
        val userContext = userContextService.getUserContext(email, groups)

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

        triggerGcveMissPathFetchAsync(allCveIds)
        val enrichmentData = fetchCveEnrichmentData(allCveIds)

        val teamRepositories = mutableMapOf<String, MutableList<no.nav.tpt.domain.GitHubVulnRepositoryDto>>()

        gitHubRepositoriesData.forEach { repo ->
            val repoVulns = gitHubRepository.getVulnerabilities(repo.nameWithOwner)

            val vulnerabilities = repoVulns.mapNotNull { vuln ->
                val cveIdentifier = vuln.identifiers
                    .firstOrNull { it.type.equals("CVE", ignoreCase = true) }
                    ?.value

                if (cveIdentifier == null) return@mapNotNull null

                val riskContext = buildRiskContext(
                    cveId = cveIdentifier,
                    severity = vuln.severity,
                    ingressTypes = emptyList(),
                    suppressed = false,
                    environment = null,
                    buildDate = null,
                    enrichmentData = enrichmentData,
                )
                val riskResult = riskScorer.calculateRiskScore(riskContext)

                val gcveDescription = if (useGcveDataSource) enrichmentData.gcveData[cveIdentifier]?.description else null

                no.nav.tpt.domain.GitHubVulnVulnerabilityDto(
                    identifier = cveIdentifier,
                    packageName = vuln.packageName,
                    packageEcosystem = vuln.packageEcosystem,
                    description = vuln.summary ?: gcveDescription ?: enrichmentData.nvdData[cveIdentifier]?.description,
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
                    usesDistroless = repo.usesDistroless,
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
