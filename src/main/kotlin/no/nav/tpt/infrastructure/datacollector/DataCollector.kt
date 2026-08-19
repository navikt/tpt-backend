package no.nav.tpt.infrastructure.datacollector

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType.Application.Json
import io.ktor.http.HttpHeaders.Accept
import io.ktor.http.HttpMethod
import io.ktor.http.HttpMethod.Companion.Post
import io.ktor.http.contentType
import java.net.URI
import kotlin.time.measureTimedValue
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory

interface DataCollector {
    suspend fun startCollectingDataFor(teamSlugs: List<String>)
}

interface GitHubDataCollector {
    suspend fun startCollectingDataFor(teamSlugs: List<String>)
}

class RealDataCollector(
    val naisTokenEndpoint: String,
    val httpClient: HttpClient = HttpClient(CIO)
) : DataCollector {
    private val logger = LoggerFactory.getLogger(RealDataCollector::class.java)

    override suspend fun startCollectingDataFor(teamSlugs: List<String>) =
        coroutineScope {
            val authToken = retrieveAccessToken()
            val responses = measureTimedValue {
                teamSlugs.map { slug ->
                    val url = URI("http", "tpt-data-collector", "/team/$slug", null).toString()
                    async { makeHttpRequest<HttpResponse>(httpMethod = Post, url = url, authToken = authToken) }
                }.awaitAll()
            }
            logger.info("Collected ${responses.value.size} responses for ${teamSlugs.size} teams in ${responses.duration}")
        }

    private suspend fun retrieveAccessToken(): String {
        val cluster = System.getenv("NAIS_CLUSTER_NAME") ?: "dev-gcp"
        val requestBody = TokenRequest("entra_id", "api://$cluster.appsec.tpt-data-collector/.default")
        logger.info("Retrieving token: {}", requestBody)
        val tokenResponse =
            makeHttpRequest<TokenResponse>(httpMethod = Post, url = naisTokenEndpoint, requestBody = requestBody)
        logger.info("Got token response, expires in: {}", tokenResponse.expiresIn)
        return tokenResponse.accessToken
    }

    private suspend inline fun <reified T> makeHttpRequest(
        httpMethod: HttpMethod,
        url: String,
        authToken: String? = null,
        requestBody: Any? = null
    ): T =
        httpClient.request(url) {
            method = httpMethod
            authToken?.let {
                logger.info("Adding Bearer token of length ${it.length} to request")
                bearerAuth(it)
            }
            header(Accept, "application/json")
            requestBody?.let {
                contentType(Json)
                setBody(it)
            }
        }.body()
}

@Serializable
private data class TokenRequest(
    @SerialName("identity_provider")
    val identityProvider: String,
    @SerialName("target")
    val target: String
)

@Serializable
private data class TokenResponse(
    @SerialName("access_token")
    val accessToken: String,
    @SerialName("expires_in")
    val expiresIn: Int,
)

@Serializable
data class GitHubCollectRequest(val teams: List<String>)

class RealGitHubDataCollector(
    val naisTokenEndpoint: String,
    val httpClient: HttpClient = HttpClient(CIO)
) : GitHubDataCollector {
    private val logger = LoggerFactory.getLogger(RealGitHubDataCollector::class.java)

    override suspend fun startCollectingDataFor(teamSlugs: List<String>) {
        val authToken = retrieveAccessToken()
        val url = URI("http", "tpt-data-collector", "/collect/github", null).toString()
        httpClient.request(url) {
            method = Post
            bearerAuth(authToken)
            header(Accept, "application/json")
            contentType(Json)
            setBody(GitHubCollectRequest(teamSlugs))
        }
        logger.info("Triggered GitHub vulnerability collection for ${teamSlugs.size} teams")
    }

    private suspend fun retrieveAccessToken(): String {
        val cluster = System.getenv("NAIS_CLUSTER_NAME") ?: "dev-gcp"
        val requestBody = TokenRequest("entra_id", "api://$cluster.appsec.tpt-data-collector/.default")
        return httpClient.request(naisTokenEndpoint) {
            method = Post
            contentType(Json)
            setBody(requestBody)
        }.body<TokenResponse>().accessToken
    }
}
