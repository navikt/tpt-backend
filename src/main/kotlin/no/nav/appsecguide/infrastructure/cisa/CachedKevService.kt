package no.nav.appsecguide.infrastructure.cisa

import no.nav.appsecguide.infrastructure.cache.Cache
import org.slf4j.LoggerFactory
import java.time.LocalDate
import java.time.format.DateTimeFormatter

class CachedKevService(
    private val kevClient: KevClient,
    private val cache: Cache<String, KevCatalog>
) : KevService {
    private val logger = LoggerFactory.getLogger(CachedKevService::class.java)

    override suspend fun getKevCatalog(): KevCatalog {
        val cacheKey = generateCacheKey()

        cache.get(cacheKey)?.let { cachedCatalog ->
            logger.info("Returning KEV catalog from cache")
            return cachedCatalog
        }

        logger.info("Fetching KEV catalog from kevClient")
        val catalog = kevClient.getKevCatalog()

        cache.put(cacheKey, catalog)

        return catalog
    }

    suspend fun getKevForCve(cveId: String): KevVulnerability? {
        val catalog = getKevCatalog()
        return catalog.vulnerabilities.firstOrNull { it.cveID == cveId }
    }

    private fun generateCacheKey(): String {
        val today = LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE)
        return "kev:$today"
    }
}

