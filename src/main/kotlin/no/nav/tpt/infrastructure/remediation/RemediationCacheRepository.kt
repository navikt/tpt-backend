package no.nav.tpt.infrastructure.remediation

import java.time.LocalDateTime

interface RemediationCacheRepository {
    suspend fun getCached(cveId: String, packageEcosystem: String): CachedRemediation?
    suspend fun saveCache(cveId: String, packageEcosystem: String, remediationText: String)
}

data class CachedRemediation(
    val remediationText: String,
    val generatedAt: LocalDateTime
)
