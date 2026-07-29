package no.nav.tpt.infrastructure.datacollector

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.http.ContentType.Application.Json
import io.ktor.http.HttpHeaders.Accept
import io.ktor.http.HttpMethod
import io.ktor.http.HttpMethod.Companion.Get
import io.ktor.http.HttpMethod.Companion.Post
import io.ktor.http.contentType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI

interface DataCollector {
    suspend fun collectDataFor(teamSlug: String): List<CheckResult>
}

class RealDataCollector(
    val naisTokenEndpoint: String,
    val httpClient: HttpClient = HttpClient(CIO)
): DataCollector {
    override suspend fun collectDataFor(teamSlug: String): List<CheckResult> {
        val authToken = retrieveAccessToken()
        val url = URI("http", "tpt-data-collector", "/team/$teamSlug", null).toString()
        val tptResponse: List<CheckResult> = makeHttpRequest(httpMethod = Get, url = url, authToken = authToken)
        return tptResponse
    }

    private suspend fun retrieveAccessToken(): String {
        val cluster = System.getenv("NAIS_CLUSTER_NAME") ?: "dev-gcp"
        val requestBody = TokenRequest("entra_id", "api://$cluster.appsec.tpt-data-collector/.default")
        val tokenResponse = makeHttpRequest<TokenResponse>(httpMethod = Post, url = naisTokenEndpoint, requestBody = requestBody)
        return tokenResponse.accessToken
    }

    private suspend inline fun <reified T> makeHttpRequest(httpMethod: HttpMethod, url: String, authToken: String? = null, requestBody: Any? = null): T =
        httpClient.request(url) {
            method = httpMethod
            authToken?.let { header("Authorization", "Bearer $it") }
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
)
