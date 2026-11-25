package no.nav.tpt.routes

import io.ktor.http.HttpStatusCode.Companion.Accepted
import io.ktor.http.HttpStatusCode.Companion.BadRequest
import io.ktor.http.HttpStatusCode.Companion.Forbidden
import io.ktor.http.HttpStatusCode.Companion.NoContent
import io.ktor.http.HttpStatusCode.Companion.Unauthorized
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingCall
import io.ktor.server.routing.get
import io.ktor.server.routing.patch
import io.ktor.server.routing.post
import kotlinx.serialization.Serializable
import no.nav.tpt.infrastructure.datacollector.DataCollector
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
            call.respond(Accepted)
        }

        get("/checks") {
            val teams = teamsForUser(call)
            if (teams.isEmpty()) {
                return@get call.respond(Unauthorized)
            }
            val checks = call.dependencies.dataCollector.allChecksFor(teams)
            call.respond(checks)
        }

        patch("/checks/{owner}/{repo}/{name}") {
            val owner = call.parameters["owner"] ?: return@patch call.respond(BadRequest)
            val repo = call.parameters["repo"] ?: return@patch call.respond(BadRequest)
            val checkName = call.parameters["name"] ?: return@patch call.respond(BadRequest)
            val repoWithOwner = "$owner/$repo"
            if (!hasPermission(call, repoWithOwner, checkName)) { return@patch call.respond(Forbidden) }
            val reqBody = call.receive<PatchRequest>()
            setSuppressionStatus(call.dependencies.dataCollector, repoWithOwner, checkName, reqBody.suppress)
            call.respond(NoContent)
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

private suspend fun hasPermission(call: RoutingCall, repoWithOwner: String, checkName: String): Boolean {
    val teams = teamsForUser(call)
    if (teams.isEmpty()) { return false }
    val requesterOwnsCheck =
        call.dependencies.dataCollector.allChecksFor(teams)
            .filter { it.repoName == repoWithOwner }
            .flatMap { it.results }
            .any { it.name == checkName }
    return requesterOwnsCheck
}

private suspend fun setSuppressionStatus(dataCollector: DataCollector, repoWithOwner: String, check: String, suppress: Boolean) {
    if (suppress) {
        dataCollector.suppress(repoWithOwner, check)
    } else {
        dataCollector.unsuppress(repoWithOwner, check)
    }
}

@Serializable
private data class PatchRequest(
    val suppress: Boolean
)


