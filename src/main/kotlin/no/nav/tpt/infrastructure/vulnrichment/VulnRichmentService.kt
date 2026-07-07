package no.nav.tpt.infrastructure.vulnrichment

import no.nav.tpt.domain.GitHubVulnResponse
import no.nav.tpt.domain.VulnResponse

interface VulnRichmentService {
    suspend fun fetchVulnerabilitiesForUser(email: String, groups: List<String> = emptyList()): VulnResponse
    suspend fun fetchVulnerabilitiesForTeam(teamSlug: String): VulnResponse
    suspend fun fetchGitHubVulnerabilitiesForUser(email: String, groups: List<String> = emptyList()): GitHubVulnResponse
}

