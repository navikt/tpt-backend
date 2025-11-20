package no.nav.appsecguide.infrastructure.config

data class AppConfig(
    val naisTokenIntrospectionEndpoint: String,
    val naisApiUrl: String,
    val naisApiToken: String,
    val valkeyHost: String,
    val valkeyPort: Int,
    val valkeyUsername: String,
    val valkeyPassword: String,
    val cacheTtlMinutes: Long
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

            val cacheTtlMinutes = System.getenv("CACHE_TTL_MINUTES")?.toLongOrNull()
                ?: 5L

            return AppConfig(
                naisTokenIntrospectionEndpoint = introspectionEndpoint,
                naisApiUrl = naisApiUrl,
                naisApiToken = naisApiToken,
                valkeyHost = valkeyHost,
                valkeyPort = valkeyPort,
                valkeyUsername = valkeyUsername,
                valkeyPassword = valkeyPassword,
                cacheTtlMinutes = cacheTtlMinutes
            )
        }
    }
}

