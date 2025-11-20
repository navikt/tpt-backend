package no.nav.appsecguide.infrastructure.nais

import no.nav.appsecguide.infrastructure.cache.ValkeyCache
import org.slf4j.LoggerFactory
import java.security.MessageDigest

class CachedNaisApiService(
    private val delegate: NaisApiClient,
    private val teamIngressCache: ValkeyCache<String, TeamIngressTypesResponse>,
    private val userAppsCache: ValkeyCache<String, ApplicationsForUserResponse>
) : NaisApiService {
    private val logger = LoggerFactory.getLogger(CachedNaisApiService::class.java)

    override suspend fun getTeamIngressTypes(teamSlug: String): TeamIngressTypesResponse {
        val cacheKey = generateCacheKey("team:$teamSlug")

        logger.debug("Checking cache for team $teamSlug (key: $cacheKey)")

        teamIngressCache.get(cacheKey)?.let { cachedResponse ->
            logger.info("Cache hit for team: $teamSlug")
            return cachedResponse
        }

        logger.info("Cache miss for team: $teamSlug - fetching from NAIS API")
        val response = delegate.getTeamIngressTypes(teamSlug)

        if (response.errors != null && response.errors.isNotEmpty()) {
            logger.warn("Not caching error response for team: $teamSlug")
        } else {
            logger.info("Caching response for team: $teamSlug (key: $cacheKey)")
            teamIngressCache.put(cacheKey, response)
        }

        return response
    }

    override suspend fun getApplicationsForUser(email: String): ApplicationsForUserResponse {
        val cacheKey = generateCacheKey("user:$email")

        logger.debug("Checking cache for user $email (key: $cacheKey)")

        userAppsCache.get(cacheKey)?.let { cachedResponse ->
            logger.info("Cache hit for user: $email")
            return cachedResponse
        }

        logger.info("Cache miss for user: $email - fetching from NAIS API")
        val response = delegate.getApplicationsForUser(email)

        if (response.errors != null && response.errors.isNotEmpty()) {
            logger.warn("Not caching error response for user: $email")
        } else {
            logger.info("Caching response for user: $email (key: $cacheKey)")
            userAppsCache.put(cacheKey, response)
        }

        return response
    }

    private fun generateCacheKey(prefix: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(prefix.toByteArray())
        return hashBytes.joinToString("") { "%02x".format(it) }.take(16)
    }
}

