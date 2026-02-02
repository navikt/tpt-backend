package no.nav.tpt.infrastructure.vulns

import no.nav.tpt.domain.GitHubVulnResponse
import no.nav.tpt.domain.VulnResponse

interface VulnService {
    suspend fun fetchVulnerabilitiesForUser(email: String, groups: List<String> = emptyList()): VulnResponse
    suspend fun fetchGitHubVulnerabilitiesForUser(email: String, groups: List<String> = emptyList()): GitHubVulnResponse
}

