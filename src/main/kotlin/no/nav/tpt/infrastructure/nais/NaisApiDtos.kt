package no.nav.tpt.infrastructure.nais

data class VulnerabilityData(
    val identifier: String,
    val severity: String,
    val packageName: String?,
    val description: String?,
    val vulnerabilityDetailsLink: String?,
    val suppressed: Boolean
)

data class WorkloadData(
    val id: String,
    val name: String,
    val workloadType: String,
    val imageTag: String?,
    val repository: String?,
    val environment: String?,
    val ingressTypes: List<String>,
    val vulnerabilities: List<VulnerabilityData>
)

data class TeamVulnerabilitiesData(
    val teamSlug: String,
    val workloads: List<WorkloadData>
)

data class UserVulnerabilitiesData(
    val teams: List<TeamVulnerabilitiesData>
)

