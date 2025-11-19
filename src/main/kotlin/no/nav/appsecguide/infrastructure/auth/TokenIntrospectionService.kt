package no.nav.appsecguide.infrastructure.auth

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Suppress("PropertyName")
@Serializable
data class IntrospectionRequest(
    val identity_provider: String,
    val token: String
)

@Serializable
data class IntrospectionResponse(
    val active: Boolean,
    val claims: Map<String, JsonElement> = emptyMap()
)

interface TokenIntrospectionService {
    suspend fun introspect(token: String): IntrospectionResponse
}

class NaisTokenIntrospectionService(
    private val httpClient: HttpClient,
    private val introspectionEndpoint: String
) : TokenIntrospectionService {
    private val logger = org.slf4j.LoggerFactory.getLogger(NaisTokenIntrospectionService::class.java)

    override suspend fun introspect(token: String): IntrospectionResponse {
        logger.debug("Introspecting token with endpoint: $introspectionEndpoint")
        try {
            val response = httpClient.post(introspectionEndpoint) {
                contentType(ContentType.Application.Json)
                setBody(IntrospectionRequest(
                    identity_provider = "azuread",
                    token = token
                ))
            }

            val introspectionResponse: IntrospectionResponse = response.body()
            logger.debug("Token introspection response - active: ${introspectionResponse.active}, claims count: ${introspectionResponse.claims.size}")
            return introspectionResponse
        } catch (e: Exception) {
            logger.error("Failed to introspect token: ${e.message}", e)
            throw e
        }
    }
}

