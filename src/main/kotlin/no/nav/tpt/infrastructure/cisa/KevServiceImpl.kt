package no.nav.tpt.infrastructure.cisa

import org.slf4j.LoggerFactory

class KevServiceImpl(
    private val kevService: KevService,
    private val kevRepository: KevRepository,
    private val staleThresholdHours: Int = 24
) : KevService {
    private val logger = LoggerFactory.getLogger(KevServiceImpl::class.java)

    override suspend fun getKevCatalog(): KevCatalog {
        val isStale = kevRepository.isCatalogStale(staleThresholdHours)

        if (!isStale) {
            kevRepository.getKevCatalog()?.let { catalog ->
                logger.debug("Returning KEV catalog from database (${catalog.vulnerabilities.size} vulnerabilities)")
                return catalog
            }
        }

        logger.info("KEV catalog is stale or missing, fetching fresh data from CISA API")

        return try {
            val freshCatalog = kevService.getKevCatalog()
            kevRepository.upsertKevCatalog(freshCatalog)
            logger.info("Successfully fetched and stored KEV catalog with ${freshCatalog.vulnerabilities.size} vulnerabilities")
            freshCatalog
        } catch (e: Exception) {
            logger.error("Failed to fetch KEV catalog from API: ${e.message}", e)
            kevRepository.getKevCatalog()?.let { staleCatalog ->
                logger.warn("Returning stale KEV catalog from database (${staleCatalog.vulnerabilities.size} vulnerabilities) due to API failure")
                staleCatalog
            } ?: run {
                logger.error("No stale KEV catalog available in database - returning empty catalog")
                KevCatalog(
                    title = "CISA Catalog of Known Exploited Vulnerabilities",
                    catalogVersion = "unavailable",
                    dateReleased = "unavailable",
                    count = 0,
                    vulnerabilities = emptyList()
                )
            }
        }
    }

    suspend fun getKevForCve(cveId: String): KevVulnerability? {
        val catalog = getKevCatalog()
        return catalog.vulnerabilities.firstOrNull { it.cveID == cveId }
    }
}
