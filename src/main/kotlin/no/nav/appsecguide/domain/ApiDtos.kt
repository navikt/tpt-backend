package no.nav.appsecguide.domain

import kotlinx.serialization.Serializable

@Serializable
data class ApplicationDto(
    val name: String,
    val ingressTypes: List<String>
)

@Serializable
data class TeamApplicationsDto(
    val team: String,
    val applications: List<ApplicationDto>
)

@Serializable
data class UserApplicationsDto(
    val teams: List<TeamApplicationsDto>
)

@Serializable
data class VulnerabilityDto(
    val identifier: String,
    val severity: String,
    val suppressed: Boolean
)

@Serializable
data class WorkloadDto(
    val name: String,
    val vulnerabilities: List<VulnerabilityDto>
)

@Serializable
data class TeamVulnerabilitiesDto(
    val team: String,
    val workloads: List<WorkloadDto>
)

@Serializable
data class UserVulnerabilitiesDto(
    val teams: List<TeamVulnerabilitiesDto>
)

