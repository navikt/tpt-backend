package no.nav.tpt.infrastructure.cisa

import java.time.Instant

interface KevRepository {
    suspend fun getKevCatalog(): KevCatalog?
    suspend fun getKevForCve(cveId: String): KevVulnerability?
    suspend fun upsertKevCatalog(catalog: KevCatalog)
    suspend fun isCatalogStale(staleThresholdHours: Int = 24): Boolean
    suspend fun getLastUpdated(): Instant?
}
