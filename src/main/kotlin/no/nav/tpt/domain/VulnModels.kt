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
    val workloadType: String,
    val environment: String?,
    val repository: String?,
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
    val riskScoreBreakdown: no.nav.tpt.domain.risk.RiskScoreBreakdown? = null
)
