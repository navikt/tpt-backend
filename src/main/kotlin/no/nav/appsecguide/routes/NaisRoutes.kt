package no.nav.appsecguide.routes

import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.routing.*
import no.nav.appsecguide.plugins.TokenPrincipal
import no.nav.appsecguide.plugins.dependencies

fun Route.naisRoutes() {
    authenticate("auth-bearer") {
        get("/applications/{teamSlug}") {
            val teamSlug = call.parameters["teamSlug"] ?: run {
                call.respondBadRequest("teamSlug path parameter is required")
                return@get
            }

            try {
                val response = call.dependencies.naisApiService.getApplicationsForTeam(teamSlug)
                call.respondWithGraphQLOrError(response, response.errors)
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch team ingresses", e)
            }
        }

        get("/applications/user") {
            val principal = call.principal<TokenPrincipal>()
            val email = principal?.preferredUsername

            if (email == null) {
                call.respondBadRequest("preferred_username claim not found in token")
                return@get
            }

            try {
                val response = call.dependencies.naisApiService.getApplicationsForUser(email)
                call.respondWithGraphQLOrError(response, response.errors)
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch applications for user", e)
            }
        }
    }
}

