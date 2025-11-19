package no.nav.appsecguide.infrastructure.auth

import kotlinx.serialization.json.JsonPrimitive

class MockTokenIntrospectionService(
    private val shouldSucceed: Boolean = false,
    private val navIdent: String? = null,
    private val preferredUsername: String? = null
) : TokenIntrospectionService {
    override suspend fun introspect(token: String): IntrospectionResponse {
        if (!shouldSucceed) {
            return IntrospectionResponse(active = false, claims = emptyMap())
        }

        val claims = mutableMapOf<String, JsonPrimitive>()
        if (navIdent != null) {
            claims["NAVident"] = JsonPrimitive(navIdent)
        }
        if (preferredUsername != null) {
            claims["preferred_username"] = JsonPrimitive(preferredUsername)
        }

        return IntrospectionResponse(active = true, claims = claims)
    }
}

