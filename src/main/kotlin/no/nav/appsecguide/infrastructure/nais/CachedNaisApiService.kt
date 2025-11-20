package no.nav.appsecguide.infrastructure.nais

import no.nav.appsecguide.infrastructure.cache.Cache
import org.slf4j.LoggerFactory
import java.security.MessageDigest

class CachedNaisApiService(
    private val delegate: NaisApiClient,
    private val cache: Cache<String, TeamIngressTypesResponse>
) : NaisApiService {
    private val logger = LoggerFactory.getLogger(CachedNaisApiService::class.java)

    override suspend fun getTeamIngressTypes(teamSlug: String): TeamIngressTypesResponse {
        val cacheKey = generateCacheKey(teamSlug)

        logger.debug("Checking cache for team $teamSlug (key: $cacheKey)")

        cache.get(cacheKey)?.let { cachedResponse ->
            logger.info("Cache hit for team: $teamSlug")
            return cachedResponse
        }

        logger.info("Cache miss for team: $teamSlug - fetching from NAIS API")
        val response = delegate.getTeamIngressTypes(teamSlug)

        if (response.errors != null && response.errors.isNotEmpty()) {
            logger.warn("Not caching error response for team: $teamSlug")
        } else {
            logger.info("Caching response for team: $teamSlug (key: $cacheKey)")
            cache.put(cacheKey, response)
        }

        return response
    }

    private fun generateCacheKey(teamSlug: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest("team:$teamSlug".toByteArray())
        return hashBytes.joinToString("") { "%02x".format(it) }.take(16)
    }
}

