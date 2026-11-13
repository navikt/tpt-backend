package no.nav.tpt.infrastructure.github.copilot

class FakeGitHubUserAuthClient : GitHubUserAuthClient {
    val revokedTokens = mutableListOf<String>()

    override fun authorizeUrl(state: String, codeChallenge: String) =
        "https://github.com/login/oauth/authorize?state=$state&code_challenge=$codeChallenge"

    override suspend fun exchangeCode(code: String, codeVerifier: String): String {
        if (code == "bad") throw GitHubApiException(200, "bad_verification_code")
        return "ghu_test"
    }

    override suspend fun revokeToken(accessToken: String) {
        revokedTokens += accessToken
    }
}
