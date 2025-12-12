package no.nav.tpt.infrastructure.nais

data class ApplicationData(
    val name: String,
    val ingressTypes: List<IngressType>,
    val environment: String?
)

data class TeamApplicationsData(
    val teamSlug: String,
    val applications: List<ApplicationData>
)

data class UserApplicationsData(
    val teams: List<TeamApplicationsData>
)

data class VulnerabilityData(
    val identifier: String,
    val severity: String,
    val packageName: String?,
    val suppressed: Boolean
)

data class WorkloadData(
    val id: String,
    val name: String,
    val imageTag: String?,
    val repository: String?,
    val vulnerabilities: List<VulnerabilityData>
)

data class TeamVulnerabilitiesData(
    val teamSlug: String,
    val workloads: List<WorkloadData>
)

data class UserVulnerabilitiesData(
    val teams: List<TeamVulnerabilitiesData>
)

