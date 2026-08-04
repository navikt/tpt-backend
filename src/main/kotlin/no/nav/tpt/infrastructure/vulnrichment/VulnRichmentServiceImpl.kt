package no.nav.tpt.infrastructure.vulnrichment

import no.nav.tpt.domain.DependencyCategory
import no.nav.tpt.domain.VulnResponse
import no.nav.tpt.domain.VulnTeamDto
import no.nav.tpt.domain.VulnVulnerabilityDto
import no.nav.tpt.domain.VulnWorkloadDto
import no.nav.tpt.domain.risk.RiskScorer
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.user.UserRole
import no.nav.tpt.domain.vulnerability.VulnerabilityDataService
import no.nav.tpt.infrastructure.gcve.GcveCveData
import no.nav.tpt.infrastructure.gcve.GcveRepository
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.nais.ImageTagParser
import no.nav.tpt.infrastructure.vulnrichment.utils.PurlParser
import no.nav.tpt.infrastructure.vulnrichment.utils.VersionMatcher
import org.slf4j.LoggerFactory

class VulnRichmentServiceImpl(
    private val vulnerabilityDataService: VulnerabilityDataService,
    private val riskScorer: RiskScorer,
    private val userContextService: UserContextService,
    private val gitHubRepository: GitHubRepository,
    private val gcveRepository: GcveRepository,
) : VulnRichmentService {
    private val logger = LoggerFactory.getLogger(VulnRichmentServiceImpl::class.java)

    private suspend fun fetchGcveData(cveIds: List<String>): Map<String, GcveCveData> =
        gcveRepository.getCveDataBatch(cveIds)

    private fun buildRiskContext(
        cveId: String,
        severity: String,
        ingressTypes: List<String>,
        suppressed: Boolean,
        environment: String?,
        buildDate: java.time.LocalDate?,
        gcveData: Map<String, GcveCveData>,
        packageName: String? = null,
    ): no.nav.tpt.domain.risk.VulnerabilityRiskContext {
        val cve = gcveData[cveId]

        return no.nav.tpt.domain.risk.VulnerabilityRiskContext(
            severity = severity,
            ingressTypes = ingressTypes,
            hasKevEntry = cve?.hasKevEntry ?: false,
            epssScore = cve?.epssScore?.epss,
            suppressed = suppressed,
            environment = environment,
            buildDate = buildDate,
            hasExploitReference = cve?.hasExploitReference ?: false,
            hasPatchReference = cve?.hasPatchReference ?: false,
            cveDaysOld = cve?.daysOld,
            hasRansomwareCampaignUse = cve?.hasRansomwareCampaignUse ?: false,
            ssvcExploitation = cve?.ssvcExploitation,
            ssvcAutomatable = cve?.ssvcAutomatable,
            ssvcTechnicalImpact = cve?.ssvcTechnicalImpact,
            hasCvssScore = cve != null && (cve.cvssV31Score != null || cve.cvssV40Score != null),
            vexNotAffected = run {
                val version = PurlParser.extractVersion(packageName)
                val type = PurlParser.extractPackageType(packageName)
                if (version != null && type != null && cve != null) {
                    VersionMatcher.isNotAffected(cve.affectedProducts, type, version)
                } else false
            },
        )
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

        val gcveData = fetchGcveData(allCveIds)

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
                        gcveData = gcveData,
                        packageName = vuln.packageName,
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

        val gcveData = fetchGcveData(allCveIds)

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
                        gcveData = gcveData,
                        packageName = vuln.packageName,
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

        val gcveData = fetchGcveData(allCveIds)

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
                    gcveData = gcveData,
                    packageName = vuln.packageName,
                )
                val riskResult = riskScorer.calculateRiskScore(riskContext)

                no.nav.tpt.domain.GitHubVulnVulnerabilityDto(
                    identifier = cveIdentifier,
                    packageName = vuln.packageName,
                    packageEcosystem = vuln.packageEcosystem,
                    description = vuln.summary ?: gcveData[cveIdentifier]?.description,
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
