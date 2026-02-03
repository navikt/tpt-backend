package no.nav.tpt.infrastructure.nais

import kotlinx.serialization.Serializable

@Serializable
data class TeamInfo(
    val slug: String,
    val slackChannel: String?
)

@Serializable
data class VulnerabilityData(
    val identifier: String,
    val severity: String,
    val packageName: String?,
    val description: String?,
    val vulnerabilityDetailsLink: String?,
    val suppressed: Boolean
)

@Serializable
data class WorkloadData(
    val id: String,
    val name: String,
    val workloadType: String,
    val imageTag: String?,
    val repository: String?,
    val environment: String?,
    val ingressTypes: List<String>,
    val createdAt: String?,
    val vulnerabilities: List<VulnerabilityData>
)

@Serializable
data class TeamVulnerabilitiesData(
    val teamSlug: String,
    val workloads: List<WorkloadData>
)

@Serializable
data class UserVulnerabilitiesData(
    val teams: List<TeamVulnerabilitiesData>
)

