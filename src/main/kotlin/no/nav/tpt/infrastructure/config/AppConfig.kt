package no.nav.tpt.infrastructure.config

data class AppConfig(
    val naisTokenIntrospectionEndpoint: String,
    val naisApiUrl: String,
    val naisApiToken: String,
    val dbJdbcUrl: String,
    val nvdApiKey: String?,
    val valkeyHost: String,
    val valkeyPort: Int,
    val valkeyUsername: String,
    val valkeyPassword: String,
    val cacheTtlMinutes: Long,
    val riskThresholdHigh: Double = 100.0,
    val riskThresholdMedium: Double = 50.0,
    val riskThresholdLow: Double = 30.0
) {
    companion object {
        fun fromEnvironment(): AppConfig {
            val introspectionEndpoint = System.getenv("NAIS_TOKEN_INTROSPECTION_ENDPOINT")
                ?: error("NAIS_TOKEN_INTROSPECTION_ENDPOINT not configured")

            val naisApiUrl = System.getenv("NAIS_API_URL")
                ?: error("NAIS_API_URL not configured")

            val naisApiToken = System.getenv("NAIS_API_TOKEN")
                ?: error("NAIS_API_TOKEN not configured")

            val valkeyInstanceName = System.getenv("VALKEY_INSTANCE_NAME")
                ?: "APPSEC"

            val valkeyHost = System.getenv("VALKEY_HOST_$valkeyInstanceName")
                ?: error("VALKEY_HOST_$valkeyInstanceName not configured")

            val valkeyPort = System.getenv("VALKEY_PORT_$valkeyInstanceName")?.toIntOrNull()
                ?: error("VALKEY_PORT_$valkeyInstanceName not configured")

            val valkeyUsername = System.getenv("VALKEY_USERNAME_$valkeyInstanceName")
                ?: error("VALKEY_USERNAME_$valkeyInstanceName not configured")

            val valkeyPassword = System.getenv("VALKEY_PASSWORD_$valkeyInstanceName")
                ?: error("VALKEY_PASSWORD_$valkeyInstanceName not configured")

            val dbJdbcUrl = System.getenv("NAIS_DATABASE_TPT_BACKEND_TPT_JDBC_URL")
                ?: error("NAIS_DATABASE_TPT_BACKEND_TPT_JDBC_URL not configured")

            val nvdApiKey = System.getenv("NVD_API_KEY")

            val cacheTtlMinutes = System.getenv("CACHE_TTL_MINUTES")?.toLongOrNull()
                ?: 5L

            val riskThresholdHigh = System.getenv("RISK_THRESHOLD_HIGH")?.toDoubleOrNull()
                ?: 100.0

            val riskThresholdMedium = System.getenv("RISK_THRESHOLD_MEDIUM")?.toDoubleOrNull()
                ?: 50.0

            val riskThresholdLow = System.getenv("RISK_THRESHOLD_LOW")?.toDoubleOrNull()
                ?: 30.0

            return AppConfig(
                naisTokenIntrospectionEndpoint = introspectionEndpoint,
                naisApiUrl = naisApiUrl,
                naisApiToken = naisApiToken,
                dbJdbcUrl = dbJdbcUrl,
                nvdApiKey = nvdApiKey,
                valkeyHost = valkeyHost,
                valkeyPort = valkeyPort,
                valkeyUsername = valkeyUsername,
                valkeyPassword = valkeyPassword,
                cacheTtlMinutes = cacheTtlMinutes,
                riskThresholdHigh = riskThresholdHigh,
                riskThresholdMedium = riskThresholdMedium,
                riskThresholdLow = riskThresholdLow
            )
        }
    }
}

