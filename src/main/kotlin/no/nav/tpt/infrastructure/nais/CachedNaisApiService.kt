package no.nav.tpt.infrastructure.nais

import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.cache.Cache
import org.slf4j.LoggerFactory

class CachedNaisApiService(
    private val apiClient: NaisApiClient,
    private val cache: Cache<String, String>
) : NaisApiService {
    private val logger = LoggerFactory.getLogger(CachedNaisApiService::class.java)
    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun getApplicationsForUser(email: String): UserApplicationsData {
        val cacheKey = "user:$email"

        cache.get(cacheKey)?.let { jsonString ->
            val response = json.decodeFromString(ApplicationsForUserResponse.serializer(), jsonString)
            return response.toData()
        }

        val response = apiClient.getApplicationsForUser(email)

        if (!response.errors.isNullOrEmpty()) {
            logger.warn("GraphQL errors for user $email: ${response.errors.joinToString { "${it.message} at ${it.path}" }}")
        } else {
            val jsonString = json.encodeToString(ApplicationsForUserResponse.serializer(), response)
            cache.put(cacheKey, jsonString)
        }

        return response.toData()
    }

    override suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData {
        val cacheKey = "vulnerabilities:user:$email"

        cache.get(cacheKey)?.let { jsonString ->
            val response = json.decodeFromString(VulnerabilitiesForUserResponse.serializer(), jsonString)
            return response.toData()
        }

        val response = apiClient.getVulnerabilitiesForUser(email)

        if (!response.errors.isNullOrEmpty()) {
            logger.warn("GraphQL errors for user vulnerabilities $email: ${response.errors.joinToString { "${it.message} at ${it.path}" }}")
        } else {
            val jsonString = json.encodeToString(VulnerabilitiesForUserResponse.serializer(), response)
            cache.put(cacheKey, jsonString)
        }

        return response.toData()
    }
}
