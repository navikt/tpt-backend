package no.nav.tpt.infrastructure.config

data class AppConfig(
    val naisTokenIntrospectionEndpoint: String,
    val naisApiUrl: String,
    val naisApiToken: String,
    val dbJdbcUrl: String,
    val nvdApiUrl: String,
    val nvdApiKey: String?,
    val epssApiUrl: String,
    val teamkatalogenUrl: String,
    val adminGroups: String?,
    val riskThresholdHigh: Double = DEFAULT_RISK_THRESHOLD_HIGH,
    val riskThresholdMedium: Double = DEFAULT_RISK_THRESHOLD_MEDIUM,
    val riskThresholdLow: Double = DEFAULT_RISK_THRESHOLD_LOW
) {
    companion object {
        const val DEFAULT_RISK_THRESHOLD_HIGH = 220.0
        const val DEFAULT_RISK_THRESHOLD_MEDIUM = 150.0
        const val DEFAULT_RISK_THRESHOLD_LOW = 100.0

        fun fromEnvironment(): AppConfig {
            val introspectionEndpoint = System.getenv("NAIS_TOKEN_INTROSPECTION_ENDPOINT")
                ?: error("NAIS_TOKEN_INTROSPECTION_ENDPOINT not configured")

            val naisApiUrl = System.getenv("NAIS_API_URL")
                ?: error("NAIS_API_URL not configured")

            val naisApiToken = System.getenv("NAIS_API_TOKEN")
                ?: error("NAIS_API_TOKEN not configured")

            val dbJdbcUrl = System.getenv("NAIS_DATABASE_TPT_BACKEND_TPT_JDBC_URL")
                ?: error("NAIS_DATABASE_TPT_BACKEND_TPT_JDBC_URL not configured")

            val nvdApiKey = System.getenv("NVD_API_KEY")

            val nvdApiUrl = System.getenv("NVD_API_URL") ?: error("NVD_API_URL not configured")

            val epssApiUrl = System.getenv("EPSS_API_URL") ?: error("EPSS_API_URL not configured")

            val teamkatalogenUrl = System.getenv("TEAMKATALOGEN_URL") ?: error("TEAMKATALOGEN_URL not configured")

            val adminGroups = System.getenv("ADMIN_GROUPS")

            return AppConfig(
                naisTokenIntrospectionEndpoint = introspectionEndpoint,
                naisApiUrl = naisApiUrl,
                naisApiToken = naisApiToken,
                dbJdbcUrl = dbJdbcUrl,
                nvdApiKey = nvdApiKey,
                nvdApiUrl = nvdApiUrl,
                epssApiUrl = epssApiUrl,
                teamkatalogenUrl = teamkatalogenUrl,
                adminGroups = adminGroups
            )
        }
    }
}

