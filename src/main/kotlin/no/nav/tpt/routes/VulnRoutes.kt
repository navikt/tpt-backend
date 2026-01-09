package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies

fun Route.vulnRoutes() {
    authenticate("auth-bearer") {
        get("/vulnerabilities/user") {
            val principal = call.principal<TokenPrincipal>()
            val email = principal?.preferredUsername

            if (email == null) {
                call.respondBadRequest("preferred_username claim not found in token")
                return@get
            }

            val bypassCache = call.request.queryParameters["bypassCache"]?.toBoolean() ?: false

            try {
                val vulnService = call.dependencies.vulnService
                val response = vulnService.fetchVulnerabilitiesForUser(email, bypassCache)
                call.respond(HttpStatusCode.OK, response)
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch vulnerabilities", e)
            }
        }
    }
}

