package no.nav.tpt.routes

import io.ktor.http.HttpStatusCode
import io.ktor.server.auth.authenticate
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import no.nav.tpt.plugins.dependencies

private val TEAM_SLUG_PATTERN = Regex("^[a-z0-9][a-z0-9-]*$")

fun Route.dataCollectorRoutes() {
    authenticate("auth-bearer") {
        get("/datacollector/{teamSlug}") {
            val teamSlug = call.pathParameters["teamSlug"] ?: ""
            if (teamSlug.isBlank() || !teamSlug.matches(TEAM_SLUG_PATTERN)) {
                call.respond(HttpStatusCode.BadRequest)
                return@get
            }
            call.respond(call.dependencies.dataCollector.collectDataFor(teamSlug))
        }
    }
}
