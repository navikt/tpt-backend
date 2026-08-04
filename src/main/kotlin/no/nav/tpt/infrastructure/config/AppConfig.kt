package no.nav.tpt.infrastructure.config

data class AppConfig(
    val naisTokenIntrospectionEndpoint: String,
    val naisTokenRetrievalEndpoint: String,
    val naisApiUrl: String,
    val naisTokenFilePath: String,
    val dbJdbcUrl: String,
    val teamkatalogenUrl: String,
    val adminGroups: String?,
    val gcveApiUrl: String = "https://db.gcve.eu/api",
    val gcveApiKey: String? = null,
    val riskThresholdCritical: Double = DEFAULT_RISK_THRESHOLD_CRITICAL,
    val riskThresholdHigh: Double = DEFAULT_RISK_THRESHOLD_HIGH,
    val riskThresholdMedium: Double = DEFAULT_RISK_THRESHOLD_MEDIUM,
    val slaCriticalWorkdays: Int = DEFAULT_SLA_CRITICAL_WORKDAYS,
    val slaNonCriticalMonths: Long = DEFAULT_SLA_NON_CRITICAL_MONTHS,
) {
    companion object {
        const val DEFAULT_RISK_THRESHOLD_CRITICAL = 75.0
        const val DEFAULT_RISK_THRESHOLD_HIGH = 50.0
        const val DEFAULT_RISK_THRESHOLD_MEDIUM = 30.0
        const val DEFAULT_SLA_CRITICAL_WORKDAYS = 1
        const val DEFAULT_SLA_NON_CRITICAL_MONTHS = 3L

        fun fromEnvironment(): AppConfig {
            val introspectionEndpoint = System.getenv("NAIS_TOKEN_INTROSPECTION_ENDPOINT")
                ?: error("NAIS_TOKEN_INTROSPECTION_ENDPOINT not configured")

            val tokenRetrievalEndpoint = System.getenv("NAIS_TOKEN_ENDPOINT")
                ?: "DoesNotMatterOutsideOfCluster"

            val naisApiUrl = System.getenv("NAIS_API_URL")
                ?: error("NAIS_API_URL not configured")

            val naisTokenFilePath = System.getenv("NAIS_SERVICE_ACCOUNT_TOKEN_PATH")
                ?: error("NAIS_SERVICE_ACCOUNT_TOKEN_PATH not configured")

            val dbJdbcUrl = System.getenv("NAIS_DATABASE_TPT_BACKEND_TPT_JDBC_URL")
                ?: error("NAIS_DATABASE_TPT_BACKEND_TPT_JDBC_URL not configured")

            val teamkatalogenUrl = System.getenv("TEAMKATALOGEN_URL") ?: error("TEAMKATALOGEN_URL not configured")

            val adminGroups = System.getenv("ADMIN_GROUPS")

            val gcveApiUrl = System.getenv("GCVE_API_URL") ?: "https://db.gcve.eu/api"
            val gcveApiKey = System.getenv("GCVE_API_KEY")

            return AppConfig(
                naisTokenIntrospectionEndpoint = introspectionEndpoint,
                naisTokenRetrievalEndpoint = tokenRetrievalEndpoint,
                naisApiUrl = naisApiUrl,
                naisTokenFilePath = naisTokenFilePath,
                dbJdbcUrl = dbJdbcUrl,
                teamkatalogenUrl = teamkatalogenUrl,
                adminGroups = adminGroups,
                gcveApiUrl = gcveApiUrl,
                gcveApiKey = gcveApiKey,
                slaCriticalWorkdays = System.getenv("SLA_CRITICAL_WORKDAYS")?.toIntOrNull() ?: DEFAULT_SLA_CRITICAL_WORKDAYS,
                slaNonCriticalMonths = System.getenv("SLA_NON_CRITICAL_MONTHS")?.toLongOrNull() ?: DEFAULT_SLA_NON_CRITICAL_MONTHS,
            )
        }
    }
}

