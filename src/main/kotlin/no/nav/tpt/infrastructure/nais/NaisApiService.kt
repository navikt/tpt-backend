package no.nav.tpt.infrastructure.nais

interface NaisApiService {
    suspend fun getVulnerabilitiesForUser(email: String, bypassCache: Boolean = false): UserVulnerabilitiesData
}

