package no.nav.appsecguide.plugins

import io.ktor.server.application.*
import io.ktor.server.auth.*
import kotlinx.serialization.json.jsonPrimitive
import no.nav.appsecguide.infrastructure.auth.TokenIntrospectionService
import org.slf4j.LoggerFactory

data class TokenPrincipal(
    val navIdent: String,
    val claims: Map<String, String>
)

fun Application.configureAuthentication(tokenIntrospectionService: TokenIntrospectionService) {
    val logger = LoggerFactory.getLogger("Authentication")

    install(Authentication) {
        bearer("auth-bearer") {
            authenticate { credential ->
                try {
                    logger.debug("Authenticating token request")
                    val introspectionResult = tokenIntrospectionService.introspect(credential.token)

                    logger.debug("Token active: ${introspectionResult.active}")
                    if (!introspectionResult.active) {
                        logger.warn("Token is not active")
                        return@authenticate null
                    }

                    val navIdent = introspectionResult.claims["NAVident"]?.jsonPrimitive?.content
                    logger.debug("NAVident from token: $navIdent")

                    if (navIdent == null) {
                        logger.warn("NAVident claim not found in token")
                        return@authenticate null
                    }

                    logger.info("User $navIdent authenticated successfully")

                    val claimsMap = introspectionResult.claims.mapValues {
                        it.value.jsonPrimitive.content
                    }
                    TokenPrincipal(navIdent, claimsMap)
                } catch (e: Exception) {
                    logger.error("Token introspection failed: ${e.message}", e)
                    null
                }
            }
        }
    }
}

