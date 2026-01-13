package no.nav.tpt.infrastructure.auth

import kotlinx.serialization.json.JsonPrimitive

class MockTokenIntrospectionService(
    private val shouldSucceed: Boolean = true,
    private val navIdent: String? = "Z999999",
    private val preferredUsername: String? = "lokal.utvikler@nav.no"
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

