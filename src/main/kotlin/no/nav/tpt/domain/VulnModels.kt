package no.nav.tpt.domain

import kotlinx.serialization.Serializable

@Serializable
data class VulnResponse(
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
    val ingressTypes: List<String>,
    val buildTime: String?,
    val vulnerabilities: List<VulnVulnerabilityDto>
)

@Serializable
data class VulnVulnerabilityDto(
    val identifier: String,
    val severity: String,
    val suppressed: Boolean,
    val hasKevEntry: Boolean,
    val epssScore: String? = null,
    val epssPercentile: String? = null
)
