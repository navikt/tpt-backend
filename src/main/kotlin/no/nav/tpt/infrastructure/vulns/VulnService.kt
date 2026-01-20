package no.nav.tpt.infrastructure.vulns

import no.nav.tpt.domain.VulnResponse

interface VulnService {
    suspend fun fetchVulnerabilitiesForUser(email: String, bypassCache: Boolean = false): VulnResponse
    suspend fun fetchGitHubVulnerabilitiesForUser(email: String): VulnResponse
}

