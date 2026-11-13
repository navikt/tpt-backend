package no.nav.tpt.infrastructure.config

data class CopilotRemediationConfig(
    val clientId: String,
    val clientSecret: String,
    val redirectUri: String,
    val gitHubWebUrl: String = "https://github.com",
    val gitHubApiUrl: String = "https://api.github.com",
) {
    override fun toString(): String =
        "CopilotRemediationConfig(clientId=$clientId, redirectUri=$redirectUri, gitHubWebUrl=$gitHubWebUrl, " +
            "gitHubApiUrl=$gitHubApiUrl)"

    companion object {
        const val DEFAULT_REDIRECT_URI = "https://tpt.nav.no/api/github/copilot/callback"

        fun fromEnvironment(): CopilotRemediationConfig? {
            val clientId = System.getenv("GITHUB_APP_CLIENT_ID")?.takeIf { it.isNotBlank() } ?: return null
            val clientSecret = System.getenv("GITHUB_APP_CLIENT_SECRET")?.takeIf { it.isNotBlank() } ?: return null
            return CopilotRemediationConfig(
                clientId = clientId,
                clientSecret = clientSecret,
                redirectUri = System.getenv("GITHUB_APP_REDIRECT_URI") ?: DEFAULT_REDIRECT_URI,
            )
        }
    }
}
