package no.nav.appsecguide.infrastructure.nais

data class ApplicationData(
    val name: String,
    val ingressTypes: List<String>
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
    val suppressed: Boolean
)

data class WorkloadData(
    val name: String,
    val vulnerabilities: List<VulnerabilityData>
)

data class TeamVulnerabilitiesData(
    val teamSlug: String,
    val workloads: List<WorkloadData>
)

data class UserVulnerabilitiesData(
    val teams: List<TeamVulnerabilitiesData>
)

