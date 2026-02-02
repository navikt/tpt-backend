package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies

fun Route.adminRoutes() {
    authenticate("auth-bearer") {
        route("/admin") {
            get("/status") {
                val principal = call.principal<TokenPrincipal>()
                
                if (principal == null) {
                    call.respondUnauthorized("Missing or invalid authentication token")
                    return@get
                }
                
                val adminAuthService = call.dependencies.adminAuthorizationService
                
                if (!adminAuthService.isAdmin(principal.groups)) {
                    call.respondForbidden("User does not have admin privileges")
                    return@get
                }
                
                call.respond(HttpStatusCode.OK, mapOf("status" to "OK"))
            }
        }
    }
}
