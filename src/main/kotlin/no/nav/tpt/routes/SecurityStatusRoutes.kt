package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.plugins.BadRequestException
import no.nav.tpt.plugins.InternalServerException
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies

fun Route.securityStatusRoutes() {
    authenticate("auth-bearer") {
        get("/security-status") {
            val principal = call.principal<TokenPrincipal>()!!
            val email = principal.preferredUsername
                ?: throw BadRequestException("preferred_username claim not found in token")

            val requestedTeams = call.request.queryParameters["teams"]
                ?.split(",")
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?.toSet()

            try {
                val userContext = call.dependencies.userContextService.getUserContext(email, principal.groups)
                val response = call.dependencies.securityStatusService.getSecurityStatus(userContext.teams, requestedTeams)
                call.respond(HttpStatusCode.OK, response)
            } catch (e: Exception) {
                throw InternalServerException("Failed to compute security status", e)
            }
        }
    }
}
