package no.nav.appsecguide.routes

import io.ktor.http.*
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.appsecguide.plugins.TokenPrincipal
import no.nav.appsecguide.plugins.dependencies

fun Route.vulnRoutes() {
    authenticate("auth-bearer") {
        get("/vulnerabilities/user") {
            val principal = call.principal<TokenPrincipal>()
            val email = principal?.preferredUsername

            if (email == null) {
                call.respondBadRequest("preferred_username claim not found in token")
                return@get
            }

            try {
                val vulnService = call.dependencies.vulnService
                val response = vulnService.fetchVulnerabilitiesForUser(email)
                call.respond(HttpStatusCode.OK, response)
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch vulnerabilities", e)
            }
        }
    }
}

