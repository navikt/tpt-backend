package no.nav.tpt.routes

import io.ktor.http.HttpStatusCode
import io.ktor.http.HttpStatusCode.Companion.OK
import io.ktor.http.HttpStatusCode.Companion.Unauthorized
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingCall
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import no.nav.tpt.plugins.BadRequestException
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies

fun Route.dataCollectorRoutes() {
    authenticate("auth-bearer") {
        post("/datacollector") {
            val teams = teamsForUser(call)
            if (teams.isEmpty()) {
                return@post call.respond(Unauthorized)
            }
            call.dependencies.dataCollector.startCollectingDataFor(teams)
            call.respond(OK)
        }

        get("/checks") {
            val teams = teamsForUser(call)
            if (teams.isEmpty()) {
                return@get call.respond(Unauthorized)
            }
            val checks = call.dependencies.dataCollector.allChecksFor(teams)
            call.respond(checks)
        }
    }
}

private suspend fun teamsForUser(call: RoutingCall): List<String> =
    call.principal<TokenPrincipal>()?.let {
        val email = it.preferredUsername
            ?: throw BadRequestException("preferred_username claim not found in token")
        val userContextService = call.dependencies.userContextService
        val userContext = userContextService.getUserContext(email, it.groups)
        userContext.teams
    } ?: emptyList()

