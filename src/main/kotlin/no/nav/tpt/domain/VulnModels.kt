package no.nav.tpt.domain

import kotlinx.serialization.Serializable
import no.nav.tpt.domain.user.UserRole

@Serializable
data class VulnResponse(
    val userRole: UserRole,
    val teams: List<VulnTeamDto>
)

@Serializable
data class VulnTeamDto(
    val team: String,
    val workloads: List<VulnWorkloadDto>
)

@Serializable
data class VulnWorkloadDto(
    val id: String,
    val name: String,
    val workloadType: String,
    val environment: String?,
    val repository: String?,
    val lastDeploy: String?,
    val vulnerabilities: List<VulnVulnerabilityDto>
)

@Serializable
data class VulnVulnerabilityDto(
    val identifier: String,
    val name: String?,
    val packageName: String?,
    val description: String?,
    val vulnerabilityDetailsLink: String?,
    val riskScore: Double,
    val riskScoreBreakdown: no.nav.tpt.domain.risk.RiskScoreBreakdown? = null,
    val dependencyScope: String? = null,
    val dependabotUpdatePullRequestUrl: String? = null,
    val publishedAt: String? = null,
    val cvssScore: Double? = null,
    val summary: String? = null,
    val packageEcosystem: String? = null
)

@Serializable
data class GitHubVulnResponse(
    val userRole: UserRole,
    val teams: List<GitHubVulnTeamDto>
)

@Serializable
data class GitHubVulnTeamDto(
    val team: String,
    val repositories: List<GitHubVulnRepositoryDto>
)

@Serializable
data class GitHubVulnRepositoryDto(
    val nameWithOwner: String,
    val usesDistroless: Boolean? = null,
    val vulnerabilities: List<GitHubVulnVulnerabilityDto>
)

@Serializable
data class GitHubVulnVulnerabilityDto(
    val identifier: String,
    val packageName: String?,
    val packageEcosystem: String?,
    val description: String?,
    val summary: String?,
    val vulnerabilityDetailsLink: String?,
    val riskScore: Double,
    val riskScoreBreakdown: no.nav.tpt.domain.risk.RiskScoreBreakdown?,
    val dependencyScope: String?,
    val dependabotUpdatePullRequestUrl: String?,
    val publishedAt: String?,
    val cvssScore: Double?
)


