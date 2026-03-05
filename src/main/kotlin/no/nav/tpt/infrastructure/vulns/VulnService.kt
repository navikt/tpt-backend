package no.nav.tpt.infrastructure.vulns

import no.nav.tpt.domain.GitHubVulnResponse
import no.nav.tpt.domain.VulnResponse
import no.nav.tpt.domain.VulnVulnerabilityDto

interface VulnService {
    suspend fun fetchVulnerabilitiesForUser(email: String, groups: List<String> = emptyList()): VulnResponse
    suspend fun fetchVulnerabilityDetail(workloadId: String, identifier: String, email: String): VulnVulnerabilityDto?
    suspend fun fetchGitHubVulnerabilitiesForUser(email: String, groups: List<String> = emptyList()): GitHubVulnResponse
}

