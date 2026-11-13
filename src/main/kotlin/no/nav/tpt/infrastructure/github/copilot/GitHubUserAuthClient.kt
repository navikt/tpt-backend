package no.nav.tpt.infrastructure.github.copilot

class GitHubApiException(val statusCode: Int, message: String) : Exception(message)

interface GitHubUserAuthClient {
    fun authorizeUrl(state: String, codeChallenge: String): String
    suspend fun exchangeCode(code: String, codeVerifier: String): String
    suspend fun revokeToken(accessToken: String)
}
