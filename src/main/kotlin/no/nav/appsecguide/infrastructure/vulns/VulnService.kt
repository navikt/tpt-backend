package no.nav.appsecguide.infrastructure.vulns

import no.nav.appsecguide.domain.VulnResponse

interface VulnService {
    suspend fun fetchVulnerabilitiesForUser(email: String): VulnResponse
}