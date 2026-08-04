package no.nav.tpt.routes

import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.http.HttpStatusCode.Companion.Unauthorized
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.post
import no.nav.tpt.plugins.BadRequestException
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies

fun Route.dataCollectorRoutes() {
    authenticate("auth-bearer") {
        post("/datacollector") {
            val principal = call.principal<TokenPrincipal>() ?:
                return@post call.respond(Unauthorized)
            val email = principal.preferredUsername
                ?: throw BadRequestException("preferred_username claim not found in token")
            val userContextService = call.dependencies.userContextService
            val userContext = userContextService.getUserContext(email, principal.groups)
            call.dependencies.dataCollector.startCollectingDataFor(userContext.teams)
            call.respond(OK)
        }
    }
}
