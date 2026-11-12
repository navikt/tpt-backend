package no.nav.tpt.infrastructure.github.copilot

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.basicAuth
import io.ktor.client.request.delete
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.header
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import no.nav.tpt.infrastructure.config.CopilotRemediationConfig
import org.slf4j.LoggerFactory

class GitHubUserAuthClientImpl(
    private val httpClient: HttpClient,
    private val config: CopilotRemediationConfig,
) : GitHubUserAuthClient {
    private val logger = LoggerFactory.getLogger(GitHubUserAuthClientImpl::class.java)

    override fun authorizeUrl(state: String, codeChallenge: String): String =
        URLBuilder("${config.gitHubWebUrl}/login/oauth/authorize").apply {
            parameters.append("client_id", config.clientId)
            parameters.append("redirect_uri", config.redirectUri)
            parameters.append("state", state)
            parameters.append("code_challenge", codeChallenge)
            parameters.append("code_challenge_method", "S256")
            parameters.append("allow_signup", "false")
        }.buildString()

    override suspend fun exchangeCode(code: String, codeVerifier: String): String {
        val response = httpClient.submitForm(
            url = "${config.gitHubWebUrl}/login/oauth/access_token",
            formParameters = parameters {
                append("client_id", config.clientId)
                append("client_secret", config.clientSecret)
                append("code", code)
                append("redirect_uri", config.redirectUri)
                append("code_verifier", codeVerifier)
            },
        ) {
            header(HttpHeaders.Accept, ContentType.Application.Json.toString())
        }
        if (!response.status.isSuccess()) {
            throw GitHubApiException(response.status.value, "GitHub token exchange failed")
        }
        val body = response.body<AccessTokenResponse>()
        return body.accessToken
            ?: throw GitHubApiException(response.status.value, "GitHub token exchange failed: ${body.error}")
    }

    override suspend fun revokeToken(accessToken: String) {
        try {
            val response = httpClient.delete("${config.gitHubApiUrl}/applications/${config.clientId}/token") {
                basicAuth(config.clientId, config.clientSecret)
                header(HttpHeaders.Accept, "application/vnd.github+json")
                header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                contentType(ContentType.Application.Json)
                setBody(RevokeTokenRequest(accessToken))
            }
            if (!response.status.isSuccess()) {
                logger.warn("Revoking GitHub user access token failed with status ${response.status.value}")
            }
        } catch (e: Exception) {
            logger.warn("Revoking GitHub user access token failed", e)
        }
    }

    @Serializable
    private data class AccessTokenResponse(
        @SerialName("access_token") val accessToken: String? = null,
        val error: String? = null,
    )

    @Serializable
    private data class RevokeTokenRequest(
        @SerialName("access_token") val accessToken: String,
    )
}
